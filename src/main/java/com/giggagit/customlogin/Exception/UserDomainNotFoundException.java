package com.giggagit.customlogin.Exception;

import org.springframework.security.core.AuthenticationException;

/**
 * DomainNotFoundException
 */
public class UserDomainNotFoundException extends AuthenticationException {

    /**
     *
     */
    private static final long serialVersionUID = 1L;

    public UserDomainNotFoundException(String msg) {
        super(msg);
    }

    public UserDomainNotFoundException(String msg, Throwable t) {
        super(msg, t);
    }

}