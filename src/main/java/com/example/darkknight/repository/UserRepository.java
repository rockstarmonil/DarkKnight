package com.example.darkknight.repository;

import com.example.darkknight.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    Optional<User> findByEmail(String email);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    // ✅ NEW: Find all users by tenant ID
    @Query("SELECT u FROM User u WHERE u.tenant.id = :tenantId")
    List<User> findByTenantId(@Param("tenantId") Long tenantId);

    // ✅ NEW: Count users by tenant ID
    @Query("SELECT COUNT(u) FROM User u WHERE u.tenant.id = :tenantId")
    long countByTenantId(@Param("tenantId") Long tenantId);

    // ✅ NEW: Find users without tenant
    @Query("SELECT u FROM User u WHERE u.tenant IS NULL")
    List<User> findUsersWithoutTenant();
}