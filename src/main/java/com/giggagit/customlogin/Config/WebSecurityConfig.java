package com.giggagit.customlogin.Config;

import com.giggagit.customlogin.Security.CustomAuthenticationDetailsSource;
import com.giggagit.customlogin.Security.CustomAuthenticationProvider;
import com.giggagit.customlogin.Security.CustomSuccessHandler;
import com.giggagit.customlogin.Service.CustomOAuth2UserService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * WebSecurityConfig
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    
    private final UserDetailsService userDetailsService;
    private final CustomOAuth2UserService oAuth2UserService;
    private final CustomSuccessHandler successHandler;
    private final CustomAuthenticationDetailsSource authenticationDetailsSource;
    private final CustomAuthenticationProvider authenticationProvider;

    public WebSecurityConfig(@Qualifier("userServiceImpl") UserDetailsService userDetailsService,
            CustomOAuth2UserService oAuth2UserService, CustomSuccessHandler successHandler,
            CustomAuthenticationDetailsSource authenticationDetailsSource,
            CustomAuthenticationProvider authenticationProvider) {
        this.userDetailsService = userDetailsService;
        this.oAuth2UserService = oAuth2UserService;
        this.successHandler = successHandler;
        this.authenticationDetailsSource = authenticationDetailsSource;
        this.authenticationProvider = authenticationProvider;
    }
    
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

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider);
    }

}