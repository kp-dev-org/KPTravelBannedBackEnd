package com.PassBanned.API.repository;


import com.PassBanned.API.Model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
    
    Optional<User> findByFlyAskySub(String flyAskySub);
    
    boolean existsByEmail(String email);
    
    long countByRole(User.Role role);
    
    long countByRoleIn(java.util.Collection<User.Role> roles);
    
    long countByStatus(User.Status status);
}