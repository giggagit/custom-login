package com.giggagit.customlogin.Config;

import com.giggagit.customlogin.Security.CustomPasswordEncoder;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * LocalAuthenticationConfig
 */
@Configuration
public class LocalAuthenticationConfig {

    private final UserDetailsService userDetailsService;
    private final CustomPasswordEncoder passwordEncoder;

    public LocalAuthenticationConfig(@Qualifier("userServiceImpl") UserDetailsService userDetailsService,
            CustomPasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Bean
    public DaoAuthenticationProvider localAuthentication() {
        DaoAuthenticationProvider localAuthentication = new DaoAuthenticationProvider();
        localAuthentication.setUserDetailsService(userDetailsService);
        localAuthentication.setPasswordEncoder(passwordEncoder.local());
        return localAuthentication;
    }

}