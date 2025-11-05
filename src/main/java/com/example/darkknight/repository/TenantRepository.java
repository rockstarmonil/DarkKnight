package com.example.darkknight.repository;

import com.example.darkknight.model.Tenant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TenantRepository extends JpaRepository<Tenant, Long> {

    Optional<Tenant> findBySubdomain(String subdomain);

    boolean existsBySubdomain(String subdomain);

    List<Tenant> findByStatus(String status);

    @Query("SELECT t FROM Tenant t WHERE t.status = 'ACTIVE'")
    List<Tenant> findAllActiveTenants();

    @Query("SELECT COUNT(u) FROM User u WHERE u.tenant.id = :tenantId")
    int countUsersByTenantId(Long tenantId);
}