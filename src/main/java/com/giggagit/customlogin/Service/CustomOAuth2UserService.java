package com.giggagit.customlogin.Service;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.UUID;

import com.giggagit.customlogin.Model.RolesModel;
import com.giggagit.customlogin.Model.UsersModel;
import com.giggagit.customlogin.Repository.RoleRepository;
import com.giggagit.customlogin.Repository.UserRepository;
import com.giggagit.customlogin.Security.CustomPasswordEncoder;

import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

/**
 * CustomOAuth2UserService
 */
@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final CustomPasswordEncoder passwordEnder;

    public CustomOAuth2UserService(UserRepository userRepository, RoleRepository roleRepository,
            CustomPasswordEncoder passwordEnder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEnder = passwordEnder;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);
        Map<String, Object> userAttribute = oAuth2User.getAttributes() ;
        UsersModel usersModel = userRepository.findByEmail((String) userAttribute.get("email"));
        
        // Create new user if no user exists
        if (usersModel == null) {
            usersModel = new UsersModel();
            usersModel.setUsername(oAuth2User.getName());
            // Set password for new user
            usersModel.setPassword(passwordEnder.local().encode(UUID.randomUUID().toString()));
        }

        String[] fullName = ((String) userAttribute.get("name")).split(" ");

        usersModel.setFirstname(fullName[0]);
        usersModel.setLastname(fullName[fullName.length - 1]);
        usersModel.setEmail((String) userAttribute.get("email"));
        usersModel.setDomain(oAuth2UserRequest.getClientRegistration().getRegistrationId());
        usersModel.setRoles(new HashSet<RolesModel>(Arrays.asList(roleRepository.findByName("ROLE_USER"))));
        userRepository.save(usersModel);

        return oAuth2User;
    }
    
}