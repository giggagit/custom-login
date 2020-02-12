package com.giggagit.customlogin.Model;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * CustomUserDetials
 */
public class CustomUserDetails implements UserDetails {

    /**
     *
     */
    private static final long serialVersionUID = 1L;
    
    private final UsersModel usersModel;

    public CustomUserDetails(UsersModel usersModel) {
        this.usersModel = usersModel;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Set<GrantedAuthority> grantedAuthorities = new HashSet<>();
        for (RolesModel roles : this.usersModel.getRoles()) {
            grantedAuthorities.add(new SimpleGrantedAuthority(roles.getName()));
        }
        return grantedAuthorities;
    }

    @Override
    public String getPassword() {
        return this.usersModel.getPassword();
    }

    @Override
    public String getUsername() {
        return this.usersModel.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    public UsersModel getUsersModel() {
        return this.usersModel;
    }

}