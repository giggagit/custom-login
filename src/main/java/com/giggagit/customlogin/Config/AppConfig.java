package com.giggagit.customlogin.Config;

import com.giggagit.customlogin.Security.CustomPasswordEncoder;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * AppConfig
 */
@Configuration
public class AppConfig {

    @Bean
    public CustomPasswordEncoder passwordEncoder() {
        return new CustomPasswordEncoder();
    }

}