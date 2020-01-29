package com.giggagit.customlogin.Security;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Service;

/**
 * CustomSuccessHandler
 */
@Service
public class CustomSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        String cookiePath = "/";
        String domain = request.getParameter("domain");

        if (domain == null || domain.isBlank()) {
            if (authentication instanceof OAuth2AuthenticationToken) {
                OAuth2AuthenticationToken oAuth2RegistrationId = (OAuth2AuthenticationToken) authentication;
                domain = oAuth2RegistrationId.getAuthorizedClientRegistrationId();
            }
        }
        
        if (request.getContextPath().length() > 0) {
            cookiePath = request.getContextPath();
        }

        // Set domain cookie after authentication success
        Cookie cookie = new Cookie("domain", domain);
        cookie.setMaxAge(1209600);
        cookie.setPath(cookiePath);
        response.addCookie(cookie);

        super.onAuthenticationSuccess(request, response, authentication);
    }
    
}