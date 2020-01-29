package com.giggagit.customlogin.Security;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Service;

/**
 * CustomAuthenticationDetailsSource
 */
@Service
public class CustomAuthenticationDetailsSource implements AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> {

    @Override
    public WebAuthenticationDetails buildDetails(HttpServletRequest context) {
        // Create new AuthenticationDetailsSource with extra login parameter
        return new CustomWebAuthenticationDetails(context);
    }

}