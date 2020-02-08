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
    
    private UsersModel users;

    public CustomUserDetails(UsersModel users) {
        this.users = users;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Set<GrantedAuthority> grantedAuthorities = new HashSet<>();
        for (RolesModel roles : this.users.getRoles()) {
            grantedAuthorities.add(new SimpleGrantedAuthority(roles.getName()));
        }
        return grantedAuthorities;
    }

    @Override
    public String getPassword() {
        return this.users.getPassword();
    }

    @Override
    public String getUsername() {
        return this.users.getUsername();
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

    public UsersModel getUsers() {
        return this.users;
    }

}