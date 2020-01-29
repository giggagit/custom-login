package com.giggagit.customlogin.Repository;

import com.giggagit.customlogin.Model.RolesModel;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * RoleRepository
 */
@Repository
public interface RoleRepository extends JpaRepository<RolesModel, Integer> {

    public RolesModel findByName(String name);
    
}