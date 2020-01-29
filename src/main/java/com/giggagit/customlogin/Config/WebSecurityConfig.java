package com.giggagit.customlogin.Config;

import com.giggagit.customlogin.Security.CustomAuthenticationDetailsSource;
import com.giggagit.customlogin.Security.CustomPasswordEncoder;
import com.giggagit.customlogin.Service.CustomOAuth2UserService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.ldap.DefaultLdapUsernameToDnMapper;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.authentication.PasswordComparisonAuthenticator;
import org.springframework.security.ldap.userdetails.InetOrgPersonContextMapper;
import org.springframework.security.ldap.userdetails.LdapUserDetailsManager;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

/**
 * WebSecurityConfig
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    
    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private CustomOAuth2UserService oAuth2UserService;
    
    @Autowired
    private AuthenticationSuccessHandler successHandler;

    @Autowired
    private CustomAuthenticationDetailsSource authenticationDetailsSource;

    @Autowired
    private AuthenticationProvider authenticationProvider;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/register/**").permitAll()
                .anyRequest().authenticated()
                .and()
            .formLogin()
                .loginPage("/login")
                .usernameParameter("username")
                .passwordParameter("password")
                .successHandler(successHandler)
                .authenticationDetailsSource(authenticationDetailsSource)
                .permitAll()
                .and()
            .oauth2Login()
                .loginPage("/login")
                .authorizationEndpoint()
                    .baseUri("/login/oauth2")
                    .and()
                .successHandler(successHandler)
                .userInfoEndpoint()
                    .userService(oAuth2UserService)
                    .and()
                .and()
            .rememberMe()
                .userDetailsService(userDetailsService)
                .key("rememberMe-Key")
                .and()
            .exceptionHandling()
                .accessDeniedPage("/access-denied")
                .and()
            .sessionManagement()
                .maximumSessions(-1)
                    .sessionRegistry(sessionRegistry())
                    .expiredUrl("/login?expired")
                    .and()
                .and()
            .logout()
                .clearAuthentication(true)
                .invalidateHttpSession(true)
                .deleteCookies("domain")
                .permitAll();
    }

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    public CustomPasswordEncoder passwordEncoder() {
        return new CustomPasswordEncoder();
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
        passwordComparisonAuthenticator.setPasswordEncoder(passwordEncoder().ldap());
        passwordComparisonAuthenticator.setPasswordAttributeName("userPassword");
        passwordComparisonAuthenticator.setUserDnPatterns(new String[] {"uid={0},ou=people"});
        passwordComparisonAuthenticator.afterPropertiesSet();
        LdapAuthenticationProvider ldapAuthenticationProvider = new LdapAuthenticationProvider(passwordComparisonAuthenticator);
        ldapAuthenticationProvider.setUserDetailsContextMapper(inetOrgPersonContextMapper());
        return ldapAuthenticationProvider;
    }

    @Bean
    public DaoAuthenticationProvider localAuthentication() {
        DaoAuthenticationProvider localAuthentication = new DaoAuthenticationProvider();
        localAuthentication.setUserDetailsService(userDetailsService);
        localAuthentication.setPasswordEncoder(passwordEncoder().local());
        return localAuthentication;
    }
    
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider);
    }
    
}