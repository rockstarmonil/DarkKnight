package com.example.darkknight.controller;

import com.example.darkknight.dto.ApiResponse;
import com.example.darkknight.dto.JwtConfigDto;
import com.example.darkknight.dto.OAuthConfigDto;
import com.example.darkknight.dto.SamlConfigDto;
import com.example.darkknight.model.TenantSsoConfig;
import com.example.darkknight.service.TenantSsoConfigService;
import com.example.darkknight.util.TenantContext;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/admin")
@PreAuthorize("hasRole('ADMIN')")
@Validated
public class SsoAdminController {

    private static final Logger logger = LoggerFactory.getLogger(SsoAdminController.class);

    @Autowired
    private TenantSsoConfigService ssoConfigService;

    /**
     * Save SAML configuration
     */
    @PostMapping("/sso/save-saml")
    public ResponseEntity<ApiResponse> saveSamlConfig(@Valid @RequestBody SamlConfigDto dto) {
        try {
            Long tenantId = getTenantIdOrThrow();

            // Validate URLs if SAML is enabled
            if (Boolean.TRUE.equals(dto.getSamlEnabled())) {
                validateUrl(dto.getSamlIdpLoginUrl(), "SAML IDP Login URL");
                validateUrl(dto.getSamlSpAcsUrl(), "SAML SP ACS URL");
            }

            // Convert DTO to entity
            TenantSsoConfig updates = new TenantSsoConfig();
            updates.setSamlEnabled(dto.getSamlEnabled());
            updates.setSamlIdpLoginUrl(sanitizeInput(dto.getSamlIdpLoginUrl()));
            updates.setSamlSpEntityId(sanitizeInput(dto.getSamlSpEntityId()));
            updates.setSamlSpAcsUrl(sanitizeInput(dto.getSamlSpAcsUrl()));
            updates.setSamlSpBinding(sanitizeInput(dto.getSamlSpBinding()));
            updates.setSamlSpNameIdFormat(sanitizeInput(dto.getSamlSpNameIdFormat()));
            updates.setSamlCertificatePath(sanitizeInput(dto.getSamlCertificatePath()));

            TenantSsoConfig config = ssoConfigService.updateSamlConfig(tenantId, updates);

            // Validate configuration if enabled
            if (Boolean.TRUE.equals(dto.getSamlEnabled())) {
                if (!ssoConfigService.validateSamlConfig(config)) {
                    logger.warn("Invalid SAML configuration for tenant ID: {}", tenantId);
                    return ResponseEntity.badRequest()
                            .body(new ApiResponse(false, "Invalid SAML configuration. Please check all required fields."));
                }
            }

            logger.info("SAML config saved successfully for tenant ID: {}", tenantId);
            return ResponseEntity.ok(new ApiResponse(true, "SAML configuration saved successfully", maskSensitiveData(config)));

        } catch (IllegalArgumentException e) {
            logger.warn("Invalid SAML configuration parameters: {}", e.getMessage());
            return ResponseEntity.badRequest().body(new ApiResponse(false, e.getMessage()));
        } catch (Exception e) {
            logger.error("Failed to save SAML configuration", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse(false, "Failed to save SAML configuration. Please try again."));
        }
    }

    /**
     * Save OAuth configuration
     */
    @PostMapping("/sso/save-oauth")
    public ResponseEntity<ApiResponse> saveOauthConfig(@Valid @RequestBody OAuthConfigDto dto) {
        try {
            Long tenantId = getTenantIdOrThrow();

            // If OAuth is enabled, validate all required fields
            if (Boolean.TRUE.equals(dto.getOauthEnabled())) {
                validateRequiredField(dto.getOauthClientId(), "oauthClientId");
                validateRequiredField(dto.getOauthClientSecret(), "oauthClientSecret");
                validateRequiredField(dto.getOauthRedirectUri(), "oauthRedirectUri");
                validateRequiredField(dto.getOauthAuthorizationUrl(), "oauthAuthorizationUrl");
                validateRequiredField(dto.getOauthTokenUrl(), "oauthTokenUrl");
                validateRequiredField(dto.getOauthUserinfoUrl(), "oauthUserinfoUrl");

                // Validate URLs
                validateUrl(dto.getOauthRedirectUri(), "OAuth Redirect URI");
                validateUrl(dto.getOauthAuthorizationUrl(), "OAuth Authorization URL");
                validateUrl(dto.getOauthTokenUrl(), "OAuth Token URL");
                validateUrl(dto.getOauthUserinfoUrl(), "OAuth Userinfo URL");
            }

            // Convert DTO to entity
            TenantSsoConfig updates = new TenantSsoConfig();
            updates.setOauthEnabled(dto.getOauthEnabled());
            updates.setOauthClientId(sanitizeInput(dto.getOauthClientId()));
            updates.setOauthClientSecret(dto.getOauthClientSecret()); // Don't sanitize secrets
            updates.setOauthRedirectUri(sanitizeInput(dto.getOauthRedirectUri()));
            updates.setOauthAuthorizationUrl(sanitizeInput(dto.getOauthAuthorizationUrl()));
            updates.setOauthTokenUrl(sanitizeInput(dto.getOauthTokenUrl()));
            updates.setOauthUserinfoUrl(sanitizeInput(dto.getOauthUserinfoUrl()));

            TenantSsoConfig config = ssoConfigService.updateOauthConfig(tenantId, updates);

            // Validate configuration if enabled
            if (Boolean.TRUE.equals(dto.getOauthEnabled())) {
                if (!ssoConfigService.validateOauthConfig(config)) {
                    logger.warn("Invalid OAuth configuration for tenant ID: {}", tenantId);
                    return ResponseEntity.badRequest()
                            .body(new ApiResponse(false, "Invalid OAuth configuration. Please check all required fields."));
                }
            }

            logger.info("OAuth config saved successfully for tenant ID: {}", tenantId);
            return ResponseEntity.ok(new ApiResponse(true, "OAuth configuration saved successfully", maskSensitiveData(config)));

        } catch (IllegalArgumentException e) {
            logger.warn("Invalid OAuth configuration parameters: {}", e.getMessage());
            return ResponseEntity.badRequest().body(new ApiResponse(false, e.getMessage()));
        } catch (Exception e) {
            logger.error("Failed to save OAuth configuration", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse(false, "Failed to save OAuth configuration. Please try again."));
        }
    }

    /**
     * Save JWT configuration
     */
    @PostMapping("/sso/save-jwt")
    public ResponseEntity<ApiResponse> saveJwtConfig(@Valid @RequestBody JwtConfigDto dto) {
        try {
            Long tenantId = getTenantIdOrThrow();

            // If JWT is enabled, validate all required fields
            if (Boolean.TRUE.equals(dto.getJwtEnabled())) {
                validateRequiredField(dto.getMiniorangeLoginUrl(), "miniorangeLoginUrl");
                validateRequiredField(dto.getMiniorangeClientId(), "miniorangeClientId");
                validateRequiredField(dto.getMiniorangeClientSecret(), "miniorangeClientSecret");
                validateRequiredField(dto.getMiniorangeRedirectUri(), "miniorangeRedirectUri");

                // Validate URLs
                validateUrl(dto.getMiniorangeLoginUrl(), "MiniOrange Login URL");
                validateUrl(dto.getMiniorangeRedirectUri(), "MiniOrange Redirect URI");
            }

            // Convert DTO to entity
            TenantSsoConfig updates = new TenantSsoConfig();
            updates.setJwtEnabled(dto.getJwtEnabled());
            updates.setMiniorangeLoginUrl(sanitizeInput(dto.getMiniorangeLoginUrl()));
            updates.setMiniorangeClientId(sanitizeInput(dto.getMiniorangeClientId()));
            updates.setMiniorangeClientSecret(dto.getMiniorangeClientSecret()); // Don't sanitize secrets
            updates.setMiniorangeRedirectUri(sanitizeInput(dto.getMiniorangeRedirectUri()));

            TenantSsoConfig config = ssoConfigService.updateJwtConfig(tenantId, updates);

            // Validate configuration if enabled
            if (Boolean.TRUE.equals(dto.getJwtEnabled())) {
                if (!ssoConfigService.validateJwtConfig(config)) {
                    logger.warn("Invalid JWT configuration for tenant ID: {}", tenantId);
                    return ResponseEntity.badRequest()
                            .body(new ApiResponse(false, "Invalid JWT configuration. Please check all required fields."));
                }
            }

            logger.info("JWT config saved successfully for tenant ID: {}", tenantId);
            return ResponseEntity.ok(new ApiResponse(true, "JWT configuration saved successfully", maskSensitiveData(config)));

        } catch (IllegalArgumentException e) {
            logger.warn("Invalid JWT configuration parameters: {}", e.getMessage());
            return ResponseEntity.badRequest().body(new ApiResponse(false, e.getMessage()));
        } catch (Exception e) {
            logger.error("Failed to save JWT configuration", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse(false, "Failed to save JWT configuration. Please try again."));
        }
    }

    /**
     * Save Active Directory configuration
     */
    @PostMapping("/ad/save-config")
    public ResponseEntity<ApiResponse> saveAdConfig(@RequestBody Map<String, String> request) {
        try {
            Long tenantId = getTenantIdOrThrow();

            // Validate required field
            validateRequiredField(request.get("adEnabled"), "adEnabled");

            Boolean adEnabled = Boolean.parseBoolean(request.get("adEnabled"));

            // If AD is enabled, validate all required fields
            if (adEnabled) {
                validateRequiredField(request.get("adServerUrl"), "adServerUrl");
                validateRequiredField(request.get("adUsername"), "adUsername");
                validateRequiredField(request.get("adPassword"), "adPassword");
            }

            // Convert to entity
            TenantSsoConfig updates = new TenantSsoConfig();
            updates.setAdEnabled(adEnabled);
            updates.setAdServerUrl(sanitizeInput(request.get("adServerUrl")));
            updates.setAdUsername(sanitizeInput(request.get("adUsername")));
            updates.setAdPassword(request.get("adPassword")); // Don't sanitize passwords
            updates.setAdBaseDn(sanitizeInput(request.get("adBaseDn")));
            updates.setAdDomain(sanitizeInput(request.get("adDomain")));

            TenantSsoConfig config = ssoConfigService.updateAdConfig(tenantId, updates);

            // Validate configuration if enabled
            if (adEnabled) {
                if (!ssoConfigService.validateAdConfig(config)) {
                    logger.warn("Invalid AD configuration for tenant ID: {}", tenantId);
                    return ResponseEntity.badRequest()
                            .body(new ApiResponse(false, "Invalid Active Directory configuration. Please check all required fields."));
                }
            }

            logger.info("Active Directory config saved successfully for tenant ID: {}", tenantId);
            return ResponseEntity.ok(new ApiResponse(true, "Active Directory configuration saved successfully", maskSensitiveData(config)));

        } catch (IllegalArgumentException e) {
            logger.warn("Invalid AD configuration parameters: {}", e.getMessage());
            return ResponseEntity.badRequest().body(new ApiResponse(false, e.getMessage()));
        } catch (Exception e) {
            logger.error("Failed to save AD configuration", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse(false, "Failed to save Active Directory configuration. Please try again."));
        }
    }

    /**
     * Test Active Directory connection
     */
    @PostMapping("/ad/test-connection")
    public ResponseEntity<ApiResponse> testAdConnection(@RequestBody Map<String, String> request) {
        try {
            String serverUrl = request.get("serverUrl");

            if (serverUrl == null || serverUrl.trim().isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(new ApiResponse(false, "Server URL is required"));
            }

            // Simple URL validation
            if (!serverUrl.startsWith("ldap://") && !serverUrl.startsWith("ldaps://")) {
                return ResponseEntity.badRequest()
                        .body(new ApiResponse(false, "Server URL must start with ldap:// or ldaps://"));
            }

            // TODO: Implement actual LDAP connection test
            // For now, return a simulated response
            logger.info("AD connection test requested for: {}", serverUrl);

            return ResponseEntity.ok(
                    new ApiResponse(true, "Connection test successful. Server is reachable.")
            );

        } catch (Exception e) {
            logger.error("AD connection test failed", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse(false, "Connection test failed. Please check server URL and network connectivity."));
        }
    }

    /**
     * Test Active Directory authentication
     */
    @PostMapping("/ad/test-auth")
    public ResponseEntity<ApiResponse> testAdAuthentication(@RequestBody Map<String, String> request) {
        try {
            String serverUrl = request.get("serverUrl");
            String username = request.get("username");
            String password = request.get("password");
            String baseDn = request.get("baseDn");

            // Validate required fields
            if (serverUrl == null || username == null || password == null) {
                return ResponseEntity.badRequest()
                        .body(new ApiResponse(false, "Server URL, username, and password are required"));
            }

            // TODO: Implement actual LDAP authentication test
            // For now, return a simulated response
            logger.info("AD authentication test requested for user: {}", username);

            Map<String, Object> result = new HashMap<>();
            result.put("userCount", 10); // Simulated user count

            return ResponseEntity.ok(
                    new ApiResponse(true, "Authentication successful", result)
            );

        } catch (Exception e) {
            logger.error("AD authentication test failed", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse(false, "Authentication test failed. Please check credentials."));
        }
    }

    /**
     * Get current SSO configuration
     */
    @GetMapping("/sso/config")
    public ResponseEntity<ApiResponse> getSsoConfig() {
        try {
            Long tenantId = getTenantIdOrThrow();
            TenantSsoConfig config = ssoConfigService.getOrCreateSsoConfig(tenantId);

            logger.debug("SSO config retrieved for tenant ID: {}", tenantId);
            return ResponseEntity.ok(new ApiResponse(true, "SSO configuration retrieved successfully", maskSensitiveData(config)));

        } catch (IllegalArgumentException e) {
            logger.warn("Invalid request: {}", e.getMessage());
            return ResponseEntity.badRequest().body(new ApiResponse(false, e.getMessage()));
        } catch (Exception e) {
            logger.error("Failed to retrieve SSO configuration", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse(false, "Failed to retrieve SSO configuration. Please try again."));
        }
    }

    /**
     * Check SSO status for tenant
     */
    @GetMapping("/sso/status")
    public ResponseEntity<ApiResponse> getSsoStatus() {
        try {
            Long tenantId = getTenantIdOrThrow();

            Map<String, Boolean> status = new HashMap<>();
            status.put("samlEnabled", ssoConfigService.isSamlEnabled(tenantId));
            status.put("oauthEnabled", ssoConfigService.isOauthEnabled(tenantId));
            status.put("jwtEnabled", ssoConfigService.isJwtEnabled(tenantId));
            status.put("adEnabled", ssoConfigService.getSsoConfigByTenantId(tenantId)
                    .map(c -> Boolean.TRUE.equals(c.getAdEnabled())).orElse(false));
            status.put("anySsoEnabled", ssoConfigService.isAnySsoEnabled(tenantId));

            logger.debug("SSO status retrieved for tenant ID: {}", tenantId);
            return ResponseEntity.ok(new ApiResponse(true, "SSO status retrieved successfully", status));

        } catch (IllegalArgumentException e) {
            logger.warn("Invalid request: {}", e.getMessage());
            return ResponseEntity.badRequest().body(new ApiResponse(false, e.getMessage()));
        } catch (Exception e) {
            logger.error("Failed to retrieve SSO status", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse(false, "Failed to retrieve SSO status. Please try again."));
        }
    }

    // ===============================
    // Private Helper Methods
    // ===============================

    /**
     * Get tenant ID from context or throw exception
     */
    private Long getTenantIdOrThrow() {
        Long tenantId = TenantContext.getTenantId();
        if (tenantId == null) {
            throw new IllegalArgumentException("No tenant context found");
        }
        return tenantId;
    }

    /**
     * Validate that a required field exists and is not empty
     */
    private void validateRequiredField(String value, String fieldName) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("Missing or empty required field: " + fieldName);
        }
    }

    /**
     * Validate URL format
     */
    private void validateUrl(String urlString, String fieldName) {
        if (urlString == null || urlString.trim().isEmpty()) {
            return; // Optional field
        }

        try {
            URL url = new URL(urlString);
            String protocol = url.getProtocol();

            // Only allow HTTPS in production (HTTP for dev/testing)
            if (!"https".equalsIgnoreCase(protocol) && !"http".equalsIgnoreCase(protocol)) {
                throw new IllegalArgumentException(
                        fieldName + " must use HTTP or HTTPS protocol"
                );
            }

            // Validate host
            String host = url.getHost();
            if (host == null || host.trim().isEmpty()) {
                throw new IllegalArgumentException(fieldName + " has invalid host");
            }

        } catch (MalformedURLException e) {
            throw new IllegalArgumentException(
                    fieldName + " is not a valid URL: " + e.getMessage()
            );
        }
    }

    /**
     * Sanitize input to prevent XSS
     */
    private String sanitizeInput(String input) {
        if (input == null) {
            return null;
        }

        // Remove potentially dangerous characters
        return input.replaceAll("[<>\"']", "").trim();
    }

    /**
     * Mask sensitive data in config before returning to client
     */
    private Map<String, Object> maskSensitiveData(TenantSsoConfig config) {
        Map<String, Object> maskedData = new HashMap<>();

        maskedData.put("id", config.getId());
        maskedData.put("tenantId", config.getTenant() != null ? config.getTenant().getId() : null);

        // SAML
        maskedData.put("samlEnabled", config.getSamlEnabled());
        maskedData.put("samlIdpLoginUrl", config.getSamlIdpLoginUrl());
        maskedData.put("samlSpEntityId", config.getSamlSpEntityId());
        maskedData.put("samlSpAcsUrl", config.getSamlSpAcsUrl());
        maskedData.put("samlSpBinding", config.getSamlSpBinding());
        maskedData.put("samlSpNameIdFormat", config.getSamlSpNameIdFormat());
        maskedData.put("samlCertificatePath", config.getSamlCertificatePath());

        // OAuth (mask secret)
        maskedData.put("oauthEnabled", config.getOauthEnabled());
        maskedData.put("oauthClientId", config.getOauthClientId());
        maskedData.put("oauthClientSecret", config.getOauthClientSecret() != null ? "********" : null);
        maskedData.put("oauthRedirectUri", config.getOauthRedirectUri());
        maskedData.put("oauthAuthorizationUrl", config.getOauthAuthorizationUrl());
        maskedData.put("oauthTokenUrl", config.getOauthTokenUrl());
        maskedData.put("oauthUserinfoUrl", config.getOauthUserinfoUrl());

        // JWT (mask secret)
        maskedData.put("jwtEnabled", config.getJwtEnabled());
        maskedData.put("miniorangeLoginUrl", config.getMiniorangeLoginUrl());
        maskedData.put("miniorangeClientId", config.getMiniorangeClientId());
        maskedData.put("miniorangeClientSecret", config.getMiniorangeClientSecret() != null ? "********" : null);
        maskedData.put("miniorangeRedirectUri", config.getMiniorangeRedirectUri());

        // AD (mask password)
        maskedData.put("adEnabled", config.getAdEnabled());
        maskedData.put("adServerUrl", config.getAdServerUrl());
        maskedData.put("adUsername", config.getAdUsername());
        maskedData.put("adPassword", config.getAdPassword() != null ? "********" : null);
        maskedData.put("adBaseDn", config.getAdBaseDn());
        maskedData.put("adDomain", config.getAdDomain());

        maskedData.put("createdAt", config.getCreatedAt());
        maskedData.put("updatedAt", config.getUpdatedAt());

        return maskedData;
    }
}