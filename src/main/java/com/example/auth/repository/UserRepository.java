package com.example.auth.repository;

import com.example.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
    
    @Modifying
    @Transactional
    @Query("UPDATE User u SET u.failedAttempts = u.failedAttempts + 1 WHERE u.username = :username")
    void incrementFailedAttempts(@Param("username") String username);
    
    @Modifying
    @Transactional
    @Query("UPDATE User u SET u.failedAttempts = 0, u.lastLogin = CURRENT_TIMESTAMP WHERE u.username = :username")
    void resetFailedAttemptsAndUpdateLogin(@Param("username") String username);
}