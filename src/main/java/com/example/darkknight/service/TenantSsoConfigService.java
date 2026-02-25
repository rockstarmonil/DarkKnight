package com.example.darkknight.service;

import com.example.darkknight.model.Tenant;
import com.example.darkknight.model.TenantSsoConfig;
import com.example.darkknight.repository.TenantRepository;
import com.example.darkknight.repository.TenantSsoConfigRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class TenantSsoConfigService {

    private static final Logger logger = LoggerFactory.getLogger(TenantSsoConfigService.class);

    @Autowired
    private TenantSsoConfigRepository ssoConfigRepository;

    @Autowired
    private TenantRepository tenantRepository;

    /**
     * Get SSO config by tenant ID
     */
    public Optional<TenantSsoConfig> getSsoConfigByTenantId(Long tenantId) {
        if (tenantId == null) {
            logger.warn("Attempted to get SSO config with null tenant ID");
            return Optional.empty();
        }
        return ssoConfigRepository.findByTenantId(tenantId);
    }

    /**
     * Get or create SSO config for a tenant
     */
    @Transactional
    public TenantSsoConfig getOrCreateSsoConfig(Long tenantId) {
        if (tenantId == null) {
            throw new IllegalArgumentException("Tenant ID cannot be null");
        }

        Optional<TenantSsoConfig> existing = ssoConfigRepository.findByTenantId(tenantId);

        if (existing.isPresent()) {
            return existing.get();
        }

        // Create new config
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new IllegalArgumentException("Tenant not found: " + tenantId));

        TenantSsoConfig newConfig = new TenantSsoConfig();
        newConfig.setTenant(tenant);
        newConfig.setCreatedAt(LocalDateTime.now());
        newConfig.setUpdatedAt(LocalDateTime.now());

        logger.info("Creating new SSO config for tenant ID: {}", tenantId);
        return ssoConfigRepository.save(newConfig);
    }

    /**
     * Save SSO configuration
     */
    @Transactional
    public TenantSsoConfig saveSsoConfig(TenantSsoConfig config) {
        if (config == null) {
            throw new IllegalArgumentException("Config cannot be null");
        }
        config.setUpdatedAt(LocalDateTime.now());
        return ssoConfigRepository.save(config);
    }

    /**
     * Update SAML configuration
     */
    @Transactional
    public TenantSsoConfig updateSamlConfig(Long tenantId, TenantSsoConfig updates) {
        if (tenantId == null) {
            throw new IllegalArgumentException("Tenant ID cannot be null");
        }
        if (updates == null) {
            throw new IllegalArgumentException("Updates cannot be null");
        }

        TenantSsoConfig config = getOrCreateSsoConfig(tenantId);

        // IdP fields — always written from UI
        config.setSamlEnabled(updates.getSamlEnabled());
        config.setSamlIdpLoginUrl(updates.getSamlIdpLoginUrl());
        config.setSamlIdpEntityId(updates.getSamlIdpEntityId());
        config.setSamlIdpCertificate(updates.getSamlIdpCertificate());

        // SP fields are auto-generated on first dashboard load (TenantAdminController).
        // The UI form does NOT submit them (readonly), so we must NOT overwrite
        // existing
        // DB values with null. Only update when a non-blank value is present.
        if (isNotEmpty(updates.getSamlSpEntityId())) {
            config.setSamlSpEntityId(updates.getSamlSpEntityId());
        }
        if (isNotEmpty(updates.getSamlSpAcsUrl())) {
            config.setSamlSpAcsUrl(updates.getSamlSpAcsUrl());
        }
        if (isNotEmpty(updates.getSamlSpBinding())) {
            config.setSamlSpBinding(updates.getSamlSpBinding());
        }
        if (isNotEmpty(updates.getSamlSpNameIdFormat())) {
            config.setSamlSpNameIdFormat(updates.getSamlSpNameIdFormat());
        }
        // Legacy classpath cert path — preserve unless explicitly overriding
        if (isNotEmpty(updates.getSamlCertificatePath())) {
            config.setSamlCertificatePath(updates.getSamlCertificatePath());
        }

        logger.debug("Updating SAML config for tenant ID: {}", tenantId);
        return saveSsoConfig(config);
    }

    /**
     * Update OAuth configuration
     */
    @Transactional
    public TenantSsoConfig updateOauthConfig(Long tenantId, TenantSsoConfig updates) {
        if (tenantId == null) {
            throw new IllegalArgumentException("Tenant ID cannot be null");
        }
        if (updates == null) {
            throw new IllegalArgumentException("Updates cannot be null");
        }

        TenantSsoConfig config = getOrCreateSsoConfig(tenantId);

        // Update only OAuth fields
        config.setOauthEnabled(updates.getOauthEnabled());
        config.setOauthClientId(updates.getOauthClientId());
        config.setOauthClientSecret(updates.getOauthClientSecret());
        // ⭐ Preserve the auto-generated redirect URI — only overwrite if a non-blank
        // value is explicitly provided. The UI never submits this (it's a readonly
        // field), so the incoming value is typically null; we must not wipe the DB.
        if (isNotEmpty(updates.getOauthRedirectUri())) {
            config.setOauthRedirectUri(updates.getOauthRedirectUri());
        }
        config.setOauthAuthorizationUrl(updates.getOauthAuthorizationUrl());
        config.setOauthTokenUrl(updates.getOauthTokenUrl());
        config.setOauthUserinfoUrl(updates.getOauthUserinfoUrl());

        logger.debug("Updating OAuth config for tenant ID: {}", tenantId);
        return saveSsoConfig(config);
    }

    /**
     * Update JWT configuration
     */
    @Transactional
    public TenantSsoConfig updateJwtConfig(Long tenantId, TenantSsoConfig updates) {
        if (tenantId == null) {
            throw new IllegalArgumentException("Tenant ID cannot be null");
        }
        if (updates == null) {
            throw new IllegalArgumentException("Updates cannot be null");
        }

        TenantSsoConfig config = getOrCreateSsoConfig(tenantId);

        // Update only JWT fields
        config.setJwtEnabled(updates.getJwtEnabled());
        config.setMiniorangeLoginUrl(updates.getMiniorangeLoginUrl());
        config.setMiniorangeClientId(updates.getMiniorangeClientId());
        config.setMiniorangeClientSecret(updates.getMiniorangeClientSecret());
        config.setMiniorangeRedirectUri(updates.getMiniorangeRedirectUri());
        // Persist the algorithm selection; default to HS256 when not provided
        if (isNotEmpty(updates.getJwtAlgorithm())) {
            config.setJwtAlgorithm(updates.getJwtAlgorithm());
        } else if (config.getJwtAlgorithm() == null || config.getJwtAlgorithm().isBlank()) {
            config.setJwtAlgorithm("HS256");
        }

        logger.debug("Updating JWT config for tenant ID: {}", tenantId);
        return saveSsoConfig(config);
    }

    /**
     * Update Active Directory configuration
     */
    @Transactional
    public TenantSsoConfig updateAdConfig(Long tenantId, TenantSsoConfig updates) {
        if (tenantId == null) {
            throw new IllegalArgumentException("Tenant ID cannot be null");
        }
        if (updates == null) {
            throw new IllegalArgumentException("Updates cannot be null");
        }

        TenantSsoConfig config = getOrCreateSsoConfig(tenantId);

        // Update only AD fields
        config.setAdEnabled(updates.getAdEnabled());
        config.setAdServerUrl(updates.getAdServerUrl());
        config.setAdUsername(updates.getAdUsername());
        config.setAdPassword(updates.getAdPassword());
        config.setAdBaseDn(updates.getAdBaseDn());
        config.setAdDomain(updates.getAdDomain());

        logger.debug("Updating Active Directory config for tenant ID: {}", tenantId);
        return saveSsoConfig(config);
    }

    /**
     * Validate SAML configuration
     */
    public boolean validateSamlConfig(TenantSsoConfig config) {
        if (config == null) {
            logger.warn("Attempted to validate null SAML config");
            return false;
        }

        if (!Boolean.TRUE.equals(config.getSamlEnabled())) {
            return true; // If disabled, it's valid
        }

        boolean isValid = isNotEmpty(config.getSamlIdpLoginUrl()) &&
                isNotEmpty(config.getSamlSpEntityId()) &&
                isNotEmpty(config.getSamlSpAcsUrl());

        if (!isValid) {
            logger.warn("SAML config validation failed for tenant: {}",
                    config.getTenant() != null ? config.getTenant().getId() : "unknown");
        }

        return isValid;
    }

    /**
     * Validate OAuth configuration
     */
    public boolean validateOauthConfig(TenantSsoConfig config) {
        if (config == null) {
            logger.warn("Attempted to validate null OAuth config");
            return false;
        }

        if (!Boolean.TRUE.equals(config.getOauthEnabled())) {
            return true; // If disabled, it's valid
        }

        boolean isValid = isNotEmpty(config.getOauthClientId()) &&
                isNotEmpty(config.getOauthClientSecret()) &&
                isNotEmpty(config.getOauthAuthorizationUrl()) &&
                isNotEmpty(config.getOauthTokenUrl()) &&
                isNotEmpty(config.getOauthUserinfoUrl()) &&
                isNotEmpty(config.getOauthRedirectUri());

        if (!isValid) {
            logger.warn("OAuth config validation failed for tenant: {}",
                    config.getTenant() != null ? config.getTenant().getId() : "unknown");
        }

        return isValid;
    }

    /**
     * Validate JWT configuration
     */
    public boolean validateJwtConfig(TenantSsoConfig config) {
        if (config == null) {
            logger.warn("Attempted to validate null JWT config");
            return false;
        }

        if (!Boolean.TRUE.equals(config.getJwtEnabled())) {
            return true; // If disabled, it's valid
        }

        boolean isValid = isNotEmpty(config.getMiniorangeLoginUrl()) &&
                isNotEmpty(config.getMiniorangeClientId()) &&
                isNotEmpty(config.getMiniorangeClientSecret());

        if (!isValid) {
            logger.warn("JWT config validation failed for tenant: {}",
                    config.getTenant() != null ? config.getTenant().getId() : "unknown");
        }

        return isValid;
    }

    /**
     * Validate Active Directory configuration
     */
    public boolean validateAdConfig(TenantSsoConfig config) {
        if (config == null) {
            logger.warn("Attempted to validate null AD config");
            return false;
        }

        if (!Boolean.TRUE.equals(config.getAdEnabled())) {
            return true; // If disabled, it's valid
        }

        boolean isValid = isNotEmpty(config.getAdServerUrl()) &&
                isNotEmpty(config.getAdUsername()) &&
                isNotEmpty(config.getAdPassword());

        if (!isValid) {
            logger.warn("Active Directory config validation failed for tenant: {}",
                    config.getTenant() != null ? config.getTenant().getId() : "unknown");
        }

        return isValid;
    }

    /**
     * Delete SSO configuration
     */
    @Transactional
    public void deleteSsoConfig(Long tenantId) {
        if (tenantId == null) {
            throw new IllegalArgumentException("Tenant ID cannot be null");
        }

        ssoConfigRepository.findByTenantId(tenantId).ifPresent(config -> {
            logger.info("Deleting SSO config for tenant ID: {}", tenantId);
            ssoConfigRepository.delete(config);
        });
    }

    /**
     * Check if SAML is enabled for tenant
     */
    public boolean isSamlEnabled(Long tenantId) {
        return getSsoConfigByTenantId(tenantId)
                .map(config -> Boolean.TRUE.equals(config.getSamlEnabled()))
                .orElse(false);
    }

    /**
     * Check if OAuth is enabled for tenant
     */
    public boolean isOauthEnabled(Long tenantId) {
        return getSsoConfigByTenantId(tenantId)
                .map(config -> Boolean.TRUE.equals(config.getOauthEnabled()))
                .orElse(false);
    }

    /**
     * Check if JWT is enabled for tenant
     */
    public boolean isJwtEnabled(Long tenantId) {
        return getSsoConfigByTenantId(tenantId)
                .map(config -> Boolean.TRUE.equals(config.getJwtEnabled()))
                .orElse(false);
    }

    /**
     * Check if any SSO is enabled for tenant
     */
    public boolean isAnySsoEnabled(Long tenantId) {
        return getSsoConfigByTenantId(tenantId)
                .map(TenantSsoConfig::isAnySsoEnabled)
                .orElse(false);
    }

    /**
     * Helper method to check if string is not empty
     */
    private boolean isNotEmpty(String value) {
        return value != null && !value.trim().isEmpty();
    }
}