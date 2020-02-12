package com.giggagit.customlogin.Config;

import com.giggagit.customlogin.Security.CustomPasswordEncoder;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.ldap.DefaultLdapUsernameToDnMapper;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.authentication.PasswordComparisonAuthenticator;
import org.springframework.security.ldap.userdetails.InetOrgPersonContextMapper;
import org.springframework.security.ldap.userdetails.LdapUserDetailsManager;

/**
 * LdapConfig
 */
@Configuration
public class LdapAuthenticationConfig {

    private final CustomPasswordEncoder passwordEncoder;

    public LdapAuthenticationConfig(CustomPasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Bean
    public InetOrgPersonContextMapper inetOrgPersonContextMapper() {
        return new InetOrgPersonContextMapper();
    }

    @Bean
    public LdapContextSource contextSource() {
        LdapContextSource ldapContextSource = new LdapContextSource();
        ldapContextSource.setUrl("ldap://localhost:10389/");
        ldapContextSource.setBase("dc=giggagit,dc=com");
        ldapContextSource.setUserDn("uid=admin,ou=system");
        ldapContextSource.setPassword("secret");
        ldapContextSource.afterPropertiesSet();
        return ldapContextSource;
    }

    @Bean
    public UserDetailsService ldapUserDetailsService() {
        LdapUserDetailsManager ldapUserDetails = new LdapUserDetailsManager(contextSource());
        ldapUserDetails.setUsernameMapper(new DefaultLdapUsernameToDnMapper("ou=people","uid"));
        ldapUserDetails.setGroupSearchBase("ou=groups");
        return ldapUserDetails;
    }

    @Bean
    public LdapTemplate ldapTemplate() throws Exception {
        LdapTemplate ldapTemplate = new LdapTemplate(contextSource());
        ldapTemplate.afterPropertiesSet();
        return ldapTemplate;
    }

    @Bean
    public LdapAuthenticationProvider ldapAuthenticationProvider() {
        PasswordComparisonAuthenticator passwordComparisonAuthenticator = new PasswordComparisonAuthenticator(contextSource());
        passwordComparisonAuthenticator.setPasswordEncoder(passwordEncoder.ldap());
        passwordComparisonAuthenticator.setPasswordAttributeName("userPassword");
        passwordComparisonAuthenticator.setUserDnPatterns(new String[] {"uid={0},ou=people"});
        passwordComparisonAuthenticator.afterPropertiesSet();
        LdapAuthenticationProvider ldapAuthenticationProvider = new LdapAuthenticationProvider(passwordComparisonAuthenticator);
        ldapAuthenticationProvider.setUserDetailsContextMapper(inetOrgPersonContextMapper());
        return ldapAuthenticationProvider;
    }

}