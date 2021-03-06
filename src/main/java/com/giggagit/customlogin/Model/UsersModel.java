package com.giggagit.customlogin.Model;

import java.io.Serializable;
import java.util.Set;

import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToMany;
import javax.persistence.Table;
import javax.persistence.Transient;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;

import com.giggagit.customlogin.GroupValidation.Password;
import com.giggagit.customlogin.GroupValidation.Profile;

/**
 * UsersModel
 */
@Entity
@Table(name = "users")
public class UsersModel implements Serializable {

    /**
     *
     */
    private static final long serialVersionUID = 1L;
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @NotBlank(groups = Profile.class)
    private String username;

    @NotBlank(groups = Profile.class)
    private String firstname;

    @NotBlank(groups = Profile.class)
    private String lastname;

    @NotBlank(groups = {Profile.class, Password.class})
    private String password;

    @Transient
    @NotBlank(groups = Password.class)
    private String passwordNew;

    @Transient
    @NotBlank(groups = {Profile.class, Password.class})
    private String passwordConfirm;

    @NotBlank(groups = Profile.class)
    private String domain;
    
    @Email(groups = Profile.class)
    private String email;

    @ManyToMany(fetch = FetchType.EAGER)
	private Set<RolesModel> roles;

    public Integer getId() {
        return this.id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getUsername() {
        return this.username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getFirstname() {
        return this.firstname;
    }

    public void setFirstname(String firstname) {
        this.firstname = firstname;
    }

    public String getLastname() {
        return this.lastname;
    }

    public void setLastname(String lastname) {
        this.lastname = lastname;
    }

    public String getPassword() {
        return this.password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getPasswordNew() {
        return this.passwordNew;
    }

    public void setPasswordNew(String passwordNew) {
        this.passwordNew = passwordNew;
    }

    public String getPasswordConfirm() {
        return this.passwordConfirm;
    }

    public void setpasswordConfirm(String passwordConfirm) {
        this.passwordConfirm = passwordConfirm;
    }

    public String getEmail() {
        return this.email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Set<RolesModel> getRoles() {
        return this.roles;
    }

    public void setRoles(Set<RolesModel> roles) {
        this.roles = roles;
    }

    public String getDomain() {
        return this.domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

}