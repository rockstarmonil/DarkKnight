package com.example.darkknight.service;

import com.example.darkknight.dto.SamlConfigDto;
import com.example.darkknight.model.Tenant;
import com.example.darkknight.model.TenantSsoConfig;
import com.example.darkknight.repository.TenantRepository;
import com.example.darkknight.repository.TenantSsoConfigRepository;
import com.example.darkknight.util.EnvironmentUtil;
import com.example.darkknight.util.TenantContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
public class TenantSsoConfigService {

    @Autowired
    private TenantSsoConfigRepository ssoConfigRepository;

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private EnvironmentUtil environmentUtil;

    /**
     * Get or create SSO configuration for a tenant
     */
    @Transactional
    public TenantSsoConfig getOrCreateSsoConfig(Long tenantId) {
        Optional<TenantSsoConfig> existingConfig = ssoConfigRepository.findByTenantId(tenantId);

        if (existingConfig.isPresent()) {
            return existingConfig.get();
        }

        // Create new config with default values
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new RuntimeException("Tenant not found"));

        TenantSsoConfig newConfig = new TenantSsoConfig();
        newConfig.setTenant(tenant);

        // Set default SP values based on tenant subdomain
        String baseUrl = environmentUtil.buildTenantUrl(tenant.getSubdomain(), "");
        newConfig.setSamlSpEntityId(baseUrl);
        newConfig.setSamlSpAcsUrl(baseUrl + "/sso/saml/callback");
        newConfig.setSamlSpBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        newConfig.setSamlSpNameIdFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");

        newConfig.setOauthRedirectUri(baseUrl + "/oauth/callback");
        newConfig.setMiniorangeRedirectUri(baseUrl + "/jwt/callback");

        newConfig.setSamlEnabled(false);
        newConfig.setOauthEnabled(false);
        newConfig.setJwtEnabled(false);

        return ssoConfigRepository.save(newConfig);
    }

    /**
     * Get SSO configuration by tenant ID
     */
    public Optional<TenantSsoConfig> getSsoConfigByTenantId(Long tenantId) {
        return ssoConfigRepository.findByTenantId(tenantId);
    }

    /**
     * Get SSO configuration for current tenant (from context)
     */
    public TenantSsoConfig getCurrentTenantSsoConfig() {
        Long tenantId = TenantContext.getTenantId();
        if (tenantId == null) {
            throw new RuntimeException("No tenant context found");
        }
        return getOrCreateSsoConfig(tenantId);
    }

    /**
     * Update SAML configuration
     */
    @Transactional
    public TenantSsoConfig updateSamlConfig(Long tenantId, SamlConfigDto dto) {
        TenantSsoConfig config = getOrCreateSsoConfig(tenantId);

        config.setSamlEnabled(dto.getSamlEnabled());
        config.setSamlIdpLoginUrl(dto.getSamlIdpLoginUrl());
        config.setSamlSpEntityId(dto.getSamlSpEntityId());
        config.setSamlSpAcsUrl(dto.getSamlSpAcsUrl());
        config.setSamlSpBinding(dto.getSamlSpBinding());
        config.setSamlSpNameIdFormat(dto.getSamlSpNameIdFormat());
        config.setSamlCertificatePath(dto.getSamlCertificatePath());

        return ssoConfigRepository.save(config);
    }

    /**
     * Update OAuth configuration
     */
    @Transactional
    public TenantSsoConfig updateOauthConfig(Long tenantId,
                                             Boolean oauthEnabled,
                                             String clientId,
                                             String clientSecret,
                                             String redirectUri,
                                             String authorizationUrl,
                                             String tokenUrl,
                                             String userinfoUrl) {
        TenantSsoConfig config = getOrCreateSsoConfig(tenantId);

        config.setOauthEnabled(oauthEnabled);
        config.setOauthClientId(clientId);
        config.setOauthClientSecret(clientSecret);
        config.setOauthRedirectUri(redirectUri);
        config.setOauthAuthorizationUrl(authorizationUrl);
        config.setOauthTokenUrl(tokenUrl);
        config.setOauthUserinfoUrl(userinfoUrl);

        return ssoConfigRepository.save(config);
    }

    /**
     * Update JWT configuration
     */
    @Transactional
    public TenantSsoConfig updateJwtConfig(Long tenantId,
                                           Boolean jwtEnabled,
                                           String loginUrl,
                                           String clientId,
                                           String clientSecret,
                                           String redirectUri) {
        TenantSsoConfig config = getOrCreateSsoConfig(tenantId);

        config.setJwtEnabled(jwtEnabled);
        config.setMiniorangeLoginUrl(loginUrl);
        config.setMiniorangeClientId(clientId);
        config.setMiniorangeClientSecret(clientSecret);
        config.setMiniorangeRedirectUri(redirectUri);

        return ssoConfigRepository.save(config);
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
     * Delete SSO configuration for tenant
     */
    @Transactional
    public void deleteSsoConfig(Long tenantId) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new RuntimeException("Tenant not found"));
        ssoConfigRepository.deleteByTenant(tenant);
    }

    /**
     * Validate SAML configuration
     */
    public boolean validateSamlConfig(TenantSsoConfig config) {
        if (!Boolean.TRUE.equals(config.getSamlEnabled())) {
            return true; // If not enabled, no validation needed
        }

        return config.getSamlIdpLoginUrl() != null && !config.getSamlIdpLoginUrl().isEmpty() &&
                config.getSamlSpEntityId() != null && !config.getSamlSpEntityId().isEmpty() &&
                config.getSamlSpAcsUrl() != null && !config.getSamlSpAcsUrl().isEmpty();
    }

    /**
     * Validate OAuth configuration
     */
    public boolean validateOauthConfig(TenantSsoConfig config) {
        if (!Boolean.TRUE.equals(config.getOauthEnabled())) {
            return true;
        }

        return config.getOauthClientId() != null && !config.getOauthClientId().isEmpty() &&
                config.getOauthClientSecret() != null && !config.getOauthClientSecret().isEmpty() &&
                config.getOauthAuthorizationUrl() != null && !config.getOauthAuthorizationUrl().isEmpty() &&
                config.getOauthTokenUrl() != null && !config.getOauthTokenUrl().isEmpty();
    }

    /**
     * Validate JWT configuration
     */
    public boolean validateJwtConfig(TenantSsoConfig config) {
        if (!Boolean.TRUE.equals(config.getJwtEnabled())) {
            return true;
        }

        return config.getMiniorangeLoginUrl() != null && !config.getMiniorangeLoginUrl().isEmpty() &&
                config.getMiniorangeClientId() != null && !config.getMiniorangeClientId().isEmpty() &&
                config.getMiniorangeClientSecret() != null && !config.getMiniorangeClientSecret().isEmpty();
    }
}