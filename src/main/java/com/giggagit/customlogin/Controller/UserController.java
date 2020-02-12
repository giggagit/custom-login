package com.giggagit.customlogin.Controller;

import java.util.List;

import com.giggagit.customlogin.GroupValidation.Password;
import com.giggagit.customlogin.GroupValidation.Profile;
import com.giggagit.customlogin.Model.CustomUserDetails;
import com.giggagit.customlogin.Model.UsersModel;
import com.giggagit.customlogin.Service.UserService;

import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.ldap.userdetails.InetOrgPerson;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.context.request.RequestContextHolder;

/**
 * UserController
 */
@Controller
public class UserController {

    private final UserService userService;
    private final SessionRegistry sessionRegistry;

    public UserController(UserService userService, SessionRegistry sessionRegistry) {
        this.userService = userService;
        this.sessionRegistry = sessionRegistry;
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping({ "/index", "/" })
    public String index(Model model,
            @CookieValue(name = "domain", required = false) String domain){
        userService.usersDomain(domain);
        model.addAttribute("domain", domain);
        
        return "index";
    }

    @GetMapping("/register")
    public String register(UsersModel usersModel) {
        return "register";
    }

    @PostMapping("/register")
    public String registerProcess(@Validated(Profile.class) UsersModel usersModel,
            BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return "register";
        } else if (userService.registerUsers(usersModel)) {
            return "redirect:/register?success";
        }

        return "redirect:/register?error";
    }

    @GetMapping("/change-password")
    public String changePassword(@CookieValue(name = "domain", required = false) String domain,
            UsersModel usersModel, Model model) {
        userService.usersDomain(domain);
        model.addAttribute("domain", domain);
        return "change-password";
    }

    @PostMapping("/change-password")
    public String changePasswordProcess(@Validated(Password.class) UsersModel usersModel,
            BindingResult bindingResult, @CookieValue(name = "domain", required = false) String domain,
            Model model) {
        userService.usersDomain(domain);

        if (bindingResult.hasErrors()) {
            model.addAttribute("domain", domain);
            return "change-password";
        } else if (userService.changePassword(usersModel, domain)) {
            String sessionUsername;
            String authenticationUsername;
            String currentSessionId = RequestContextHolder.currentRequestAttributes().getSessionId();
            Object currentPrincipal = userService.currentUsers().getPrincipal();
            List<Object> principals = sessionRegistry.getAllPrincipals();
    
            // Get user class and expire
            for (Object principal : principals) {                
                if (principal instanceof CustomUserDetails && currentPrincipal instanceof CustomUserDetails) {
                    CustomUserDetails sessionPrincipal = (CustomUserDetails) principal;
                    CustomUserDetails userDetails = (CustomUserDetails) userService.currentUsers().getPrincipal();
                    sessionUsername = sessionPrincipal.getUsername();
                    authenticationUsername = userDetails.getUsername();
                    expireUsers(authenticationUsername, sessionUsername, currentSessionId, principal);
                } else if (principal instanceof InetOrgPerson && currentPrincipal instanceof InetOrgPerson) {
                    InetOrgPerson sessionPrincipal = (InetOrgPerson) principal;
                    InetOrgPerson userDetails = (InetOrgPerson) userService.currentUsers().getPrincipal();
                    sessionUsername = sessionPrincipal.getUsername();
                    authenticationUsername = userDetails.getUsername();
                    expireUsers(authenticationUsername, sessionUsername, currentSessionId, principal);
                } else if (principal instanceof DefaultOAuth2User && currentPrincipal instanceof DefaultOAuth2User) {
                    DefaultOAuth2User sessionPrincipal = (DefaultOAuth2User) principal;
                    DefaultOAuth2User userDetails = (DefaultOAuth2User) userService.currentUsers().getPrincipal();
                    sessionUsername = (String) sessionPrincipal.getName();
                    authenticationUsername = (String) userDetails.getName();
                    expireUsers(authenticationUsername, sessionUsername, currentSessionId, principal);
                }
            }

            return "redirect:/change-password?success";
        }

        return "redirect:/change-password?error";
    }

    private void expireUsers(String authenticationUsername, String sessionUsername,String currentSessionId, Object principal) {
        if (authenticationUsername.equals(sessionUsername)) {
            List<SessionInformation> sessionInformations = sessionRegistry.getAllSessions(principal, false);
            
            for (SessionInformation sessionInformation : sessionInformations) {
                // Logout user form other device
                if (sessionInformation.getSessionId() != currentSessionId) {
                    sessionInformation.expireNow();
                }
            }
        }
    }
    
}