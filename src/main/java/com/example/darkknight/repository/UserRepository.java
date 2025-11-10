package com.example.darkknight.repository;

import com.example.darkknight.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Find user by email
     */
    Optional<User> findByEmail(String email);

    /**
     * Find user by username
     */
    Optional<User> findByUsername(String username);

    /**
     * Find user by email and tenant ID (for multi-tenant SSO)
     */
    Optional<User> findByEmailAndTenantId(String email, Long tenantId);

    /**
     * Find all users by tenant ID
     */
    List<User> findByTenantId(Long tenantId);

    /**
     * Count users by tenant ID
     */
    long countByTenantId(Long tenantId);

    /**
     * Check if user exists by email
     */
    boolean existsByEmail(String email);

    /**
     * Check if user exists by username
     */
    boolean existsByUsername(String username);

    /**
     * Find all enabled users by tenant ID
     */
    List<User> findByTenantIdAndEnabledTrue(Long tenantId);

    /**
     * Count enabled users by tenant ID
     */
    long countByTenantIdAndEnabledTrue(Long tenantId);
}