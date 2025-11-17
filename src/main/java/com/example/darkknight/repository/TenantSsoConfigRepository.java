package com.example.darkknight.repository;

import com.example.darkknight.model.TenantSsoConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface TenantSsoConfigRepository extends JpaRepository<TenantSsoConfig, Long> {

    /**
     * Find SSO config by tenant ID
     */
    Optional<TenantSsoConfig> findByTenantId(Long tenantId);

    /**
     * Check if SSO config exists for tenant
     */
    boolean existsByTenantId(Long tenantId);

    /**
     * Delete SSO config by tenant ID
     */
    void deleteByTenantId(Long tenantId);
}