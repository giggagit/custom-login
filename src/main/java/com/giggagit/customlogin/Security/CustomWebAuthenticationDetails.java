package com.giggagit.customlogin.Security;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.authentication.WebAuthenticationDetails;

/**
 * CustomWebAuthenticationDetails
 */
public class CustomWebAuthenticationDetails extends WebAuthenticationDetails {

    /**
     *
     */
    private static final long serialVersionUID = 1L;
    private String domain;

    public CustomWebAuthenticationDetails(HttpServletRequest request) {
        super(request);
        // Set extra login parameter to authentication details
        domain = request.getParameter("domain");
    }

    public String getDomain() {
        return this.domain;
    }

}