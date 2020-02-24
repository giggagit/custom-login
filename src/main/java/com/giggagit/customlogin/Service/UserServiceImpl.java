package com.giggagit.customlogin.Service;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.naming.Name;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import com.giggagit.customlogin.Exception.UserDomainNotFoundException;
import com.giggagit.customlogin.Model.CustomUserDetails;
import com.giggagit.customlogin.Model.UsersModel;
import com.giggagit.customlogin.Repository.RoleRepository;
import com.giggagit.customlogin.Repository.UserRepository;
import com.giggagit.customlogin.Security.CustomPasswordEncoder;

import org.apache.log4j.Logger;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.support.LdapNameBuilder;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.userdetails.InetOrgPerson;
import org.springframework.security.ldap.userdetails.InetOrgPersonContextMapper;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * UserServiceImpl
 */
@Service
public class UserServiceImpl implements UserService {

    final static Logger logger = Logger.getLogger(UserServiceImpl.class);
    
    private final HttpServletRequest request;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final LdapTemplate ldapTemplate;
    private final CustomPasswordEncoder passwordEncoder;

    public UserServiceImpl(HttpServletRequest request, UserRepository userRepository,
            RoleRepository roleRepository, LdapTemplate ldapTemplate, CustomPasswordEncoder passwordEncoder) {
        this.request = request;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.ldapTemplate = ldapTemplate;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDetails userDetials = null;
        String domain = request.getParameter("domain");

        if (domain == null) {
            Cookie[] cookies = request.getCookies();

            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("domain")) {
                    domain = cookie.getValue().toLowerCase();
                }
            }

            usersDomain(domain);
        }

        switch (domain) {
            case "local":
                UsersModel usersModel = findByUsername(username);
                
                if (usersModel == null) {
                    throw new UsernameNotFoundException("Invalid username or password.");
                }

                userDetials = new CustomUserDetails(usersModel);
                break;
            case "ldap":
                // Load ldap user as UserDetails for remember-me service
                Name dn = LdapNameBuilder
                    .newInstance()
                    .add("ou", "people")
                    .add("uid", username)
                    .build();
                Set<GrantedAuthority> grantedAuthorities = new HashSet<>();
                grantedAuthorities.add(new SimpleGrantedAuthority("USER"));
                DirContextOperations context = ldapTemplate.lookupContext(dn);
                userDetials = new InetOrgPersonContextMapper().mapUserFromContext(context, username, grantedAuthorities);
                break;
            default:
                throw new UserDomainNotFoundException("User domain not found");
        }

        return userDetials;
    }
    
    @Override
    public void saveUsers(UsersModel usersModel) {
        userRepository.save(usersModel);
    }

    @Override
    public UsersModel findByEmail(String email) {
        UsersModel usersModel = userRepository.findByEmail(email);
        return usersModel;
    }

    @Override
    public UsersModel findByUsername(String username) {
        UsersModel usersModel = userRepository.findByUsername(username);
        return usersModel;
    }

    @Override
    public UsersModel findByUsernameAndDomain(String username, String domain) {
        UsersModel usersModel = userRepository.findByUsernameAndDomain(username, domain);
        return usersModel;
    }

    @Override
    public UsersModel findByEmailAndDomain(String username, String domain) {
        UsersModel usersModel = userRepository.findByEmailAndDomain(username, domain);
        return usersModel;
    }

    @Override
    public void usersDomain(String domain) throws UserDomainNotFoundException {
        if (domain == null || domain.isEmpty() || domainList(domain)) {
            throw new UserDomainNotFoundException("User domain not found");
        }
    }

    @Override
    public Authentication currentUsers() throws AccessDeniedException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null) {
            throw new AccessDeniedException("Access Denied");
        }

        return authentication;
    }

    @Override
    public Boolean registerUsers(UsersModel usersModel) throws UserDomainNotFoundException {
        Boolean registerStatus = false;
        String userDomain = usersModel.getDomain().toLowerCase();

        // Compare user password with confirm password
        if (usersModel.getPassword().equals(usersModel.getPasswordConfirm())) {
            switch (userDomain) {
                case "local":
                     // Search local user exists
                    if (findByUsernameAndDomain(usersModel.getUsername(), userDomain) == null) {
                        // Save local user to  database
                        usersModel.setRoles(new HashSet<>(Arrays.asList(roleRepository.findByName("ROLE_USER"))));
                        usersModel.setPassword(passwordEncoder.local().encode(usersModel.getPassword()));
                        saveUsers(usersModel);
                        registerStatus = true;
                    }

                    break;
                case "ldap":
                    // Search ldap user exists
                    List<String> ldapList = ldapTemplate
                    .search(
                        "ou=people",
                        "uid=" + usersModel.getUsername(),
                        (AttributesMapper<String>) args -> (String) args.get("uid").get());
                
                    if (ldapList.isEmpty()) {
                        // Create ldap user and bind it to ldap server
                        Name dn = LdapNameBuilder
                            .newInstance()
                            .add("ou", "people")
                            .add("uid", usersModel.getUsername())
                            .build();
                        DirContextAdapter context = new DirContextAdapter(dn);

                        context.setAttributeValues("objectClass", new String[] {"organizationalPerson", "inetOrgPerson", "top", "person"});
                        context.setAttributeValue("cn", usersModel.getFirstname() + " " + usersModel.getLastname());
                        context.setAttributeValue("sn", usersModel.getLastname());
                        context.setAttributeValue("givenName", usersModel.getFirstname());
                        context.setAttributeValue("mail", usersModel.getEmail());
                        context.setAttributeValue("uid", usersModel.getUsername());
                        context.setAttributeValue("userPassword", passwordEncoder.ldap().encode(usersModel.getPassword()));

                        ldapTemplate.bind(context);

                        // Add ldap user to groups
                        Name gp = LdapNameBuilder
                            .newInstance()
                            .add("ou", "groups")
                            .add("cn", "users")
                            .build();
                        DirContextOperations ctx = ldapTemplate.lookupContext(gp);
                        ctx.addAttributeValue("uniqueMember","uid=" + usersModel.getUsername() + ",ou=people,dc=giggagit,dc=com");
                        ldapTemplate.modifyAttributes(ctx);
                        registerStatus = true;
                    }

                    break;
                default:
                    throw new UserDomainNotFoundException("User domain not found");
            }
        }

        return registerStatus;
    }

    @Override
    public Boolean changePassword(UsersModel usersModel, String domain)
            throws UsernameNotFoundException {
        Boolean changeStatus = false;
        String userDomain = domain.toLowerCase();
        Object principal = currentUsers().getPrincipal();

        if (principal instanceof CustomUserDetails || principal instanceof DefaultOAuth2User) {
            UsersModel getUsersModel = null;
            Boolean getPrincipal = false;

            if (principal instanceof CustomUserDetails)  {
                CustomUserDetails userDetails = (CustomUserDetails) principal;
                getUsersModel = findByUsernameAndDomain(userDetails.getUsername(), userDomain);

                // Compare current password
                if (getUsersModel == null) {
                    throw new UsernameNotFoundException("Username not Found.");
                } else if (passwordEncoder.local().matches(usersModel.getPassword(), getUsersModel.getPassword())) {
                    getPrincipal = true;
                }
                
            } else if (principal instanceof DefaultOAuth2User) {
                DefaultOAuth2User oAuth2User = (DefaultOAuth2User) principal;
                getUsersModel = findByUsernameAndDomain(oAuth2User.getName(), userDomain);

                if (getUsersModel == null) {
                    throw new UsernameNotFoundException("Username not Found.");
                }

                // Not Compare password fo oAuth2 user
                getPrincipal = true;
            }

            if (getPrincipal) {
                // Compare new password
                if (usersModel.getPasswordNew().equals(usersModel.getPasswordConfirm())) {
                    getUsersModel.setPassword(passwordEncoder.local().encode(usersModel.getPasswordNew()));
                    saveUsers(getUsersModel);
                    changeStatus = true;
                }
            }
        } else if (principal instanceof InetOrgPerson) {
            InetOrgPerson ldapUsers = (InetOrgPerson) currentUsers().getPrincipal();

            Name dn = LdapNameBuilder
                .newInstance()
                .add("ou", "people")
                .add("uid", ldapUsers.getUid())
                .build();

            // Compare current ldap user password by re-authenticate
            if (ldapTemplate.authenticate(dn, "(objectClass=person)", usersModel.getPassword())) {
                // Compare new password
                if (usersModel.getPasswordNew().equals(usersModel.getPasswordConfirm())) {
                    DirContextOperations context = ldapTemplate.lookupContext(dn);

                    context.setAttributeValues("objectClass", new String[] {"organizationalPerson", "inetOrgPerson", "top", "person"});
                    context.setAttributeValue("cn", ldapUsers.getGivenName() + " " + ldapUsers.getSn());
                    context.setAttributeValue("sn", ldapUsers.getSn());
                    context.setAttributeValue("givenName", ldapUsers.getGivenName());
                    context.setAttributeValue("mail", ldapUsers.getMail());
                    context.setAttributeValue("uid", ldapUsers.getUid());
                    context.setAttributeValue("userPassword", usersModel.getPasswordNew());

                    ldapTemplate.modifyAttributes(context);
                    changeStatus = true;
                }
            }
        }

        return changeStatus;
    }
    
    private Boolean domainList(String domain) {
        return !domain.equalsIgnoreCase("local") && !domain.equalsIgnoreCase("ldap") &&
                !domain.equalsIgnoreCase("facebook") && !domain.equalsIgnoreCase("google");
    }
    
}