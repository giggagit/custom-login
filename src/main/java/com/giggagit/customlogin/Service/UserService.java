package com.giggagit.customlogin.Service;

import com.giggagit.customlogin.Exception.UserDomainNotFoundException;
import com.giggagit.customlogin.Form.ChangePassword;
import com.giggagit.customlogin.Model.UsersModel;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * UserService
 */
public interface UserService extends UserDetailsService {

    public void saveUsers(UsersModel usersModel);
    public UsersModel findByEmail(String email);
    public UsersModel findByUsername(String username);
    public UsersModel findByUsernameAndDomain(String username, String domain);
    public UsersModel findByEmailAndDomain(String username, String domain);
    public void usersDomain(String domain) throws UserDomainNotFoundException;
    public Authentication currentUsers();
    public Boolean registerUsers(UsersModel usersModel) throws UserDomainNotFoundException;
    public Boolean changePassword(ChangePassword changePassword, String domain)
            throws AccessDeniedException, UsernameNotFoundException;
            
}