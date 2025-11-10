package com.example.darkknight.repository;

import com.example.darkknight.model.Tenant;
import com.example.darkknight.model.TenantSsoConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


import java.util.Optional;

@Repository
public interface TenantSsoConfigRepository extends JpaRepository<TenantSsoConfig, Long> {

    /**
     * Find SSO configuration by tenant
     */
    Optional<TenantSsoConfig> findByTenant(Tenant tenant);

    /**
     * Find SSO configuration by tenant ID
     */
    Optional<TenantSsoConfig> findByTenantId(Long tenantId);

    /**
     * Check if SSO configuration exists for tenant
     */
    boolean existsByTenantId(Long tenantId);

    /**
     * Delete SSO configuration by tenant
     */
    void deleteByTenant(Tenant tenant);
}