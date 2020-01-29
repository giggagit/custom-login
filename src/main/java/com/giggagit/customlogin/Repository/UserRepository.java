package com.giggagit.customlogin.Repository;

import com.giggagit.customlogin.Model.UsersModel;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * UserRepository
 */
@Repository
public interface UserRepository extends JpaRepository<UsersModel, Integer> {

    public UsersModel findByUsername(String username);
    public UsersModel findByEmail(String email);
    public UsersModel findByUsernameAndDomain(String username, String domain);
    public UsersModel findByEmailAndDomain(String username, String domain);
    
}