package com.giggagit.customlogin.Security;

import com.giggagit.customlogin.Exception.UserDomainNotFoundException;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.stereotype.Service;

/**
 * CustomAuthenticationProvider
 */
@Service
public class CustomAuthenticationProvider implements AuthenticationProvider {
    
    private final LdapAuthenticationProvider ldapAuthenticationProvider;
    private final DaoAuthenticationProvider localAuthentication;

    public CustomAuthenticationProvider(LdapAuthenticationProvider ldapAuthenticationProvider,
            DaoAuthenticationProvider localAuthentication) {
        this.ldapAuthenticationProvider = ldapAuthenticationProvider;
        this.localAuthentication = localAuthentication;
    }
    
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String domain = ((CustomWebAuthenticationDetails) authentication.getDetails()).getDomain().toLowerCase();
        Authentication domainAuthentication = null;
        
        switch (domain) {
            case "local":
                domainAuthentication = localAuthentication.authenticate(authentication);
                break;
            case "ldap":
                domainAuthentication = ldapAuthenticationProvider.authenticate(authentication);
                break;
            default:
                throw new UserDomainNotFoundException("Invalid user domain");
        }

        return domainAuthentication;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }

}