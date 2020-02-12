package com.giggagit.customlogin.Security;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * CustomPasswordEncoder
 */
@Service
@SuppressWarnings("deprecation")
public class CustomPasswordEncoder {

    public PasswordEncoder local() {
        return new BCryptPasswordEncoder();
    }

    public PasswordEncoder ldap() {
        return new LdapShaPasswordEncoder();
    }
    
}