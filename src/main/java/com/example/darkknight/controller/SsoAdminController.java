package com.example.darkknight.controller;

import com.example.darkknight.dto.SamlConfigDto;
import com.example.darkknight.model.TenantSsoConfig;
import com.example.darkknight.service.TenantSsoConfigService;
import com.example.darkknight.util.TenantContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/admin/sso")
@PreAuthorize("hasRole('ADMIN')")
public class SsoAdminController {

    @Autowired
    private TenantSsoConfigService ssoConfigService;

    /**
     * Save SAML configuration
     */
    @PostMapping("/save-saml")
    public ResponseEntity<Map<String, Object>> saveSamlConfig(@RequestBody SamlConfigDto dto) {
        Map<String, Object> response = new HashMap<>();

        try {
            Long tenantId = TenantContext.getTenantId();
            if (tenantId == null) {
                response.put("success", false);
                response.put("message", "No tenant context found");
                return ResponseEntity.badRequest().body(response);
            }

            TenantSsoConfig config = ssoConfigService.updateSamlConfig(tenantId, dto);

            // Validate configuration if enabled
            if (Boolean.TRUE.equals(dto.getSamlEnabled())) {
                if (!ssoConfigService.validateSamlConfig(config)) {
                    response.put("success", false);
                    response.put("message", "Invalid SAML configuration. Please check all required fields.");
                    return ResponseEntity.badRequest().body(response);
                }
            }

            response.put("success", true);
            response.put("message", "SAML configuration saved successfully");
            response.put("data", config);

            System.out.println("✅ SAML config saved for tenant ID: " + tenantId);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            e.printStackTrace();
            response.put("success", false);
            response.put("message", "Failed to save SAML configuration: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    /**
     * Save OAuth configuration
     */
    @PostMapping("/save-oauth")
    public ResponseEntity<Map<String, Object>> saveOauthConfig(@RequestBody Map<String, String> request) {
        Map<String, Object> response = new HashMap<>();

        try {
            Long tenantId = TenantContext.getTenantId();
            if (tenantId == null) {
                response.put("success", false);
                response.put("message", "No tenant context found");
                return ResponseEntity.badRequest().body(response);
            }

            Boolean oauthEnabled = Boolean.parseBoolean(request.get("oauthEnabled"));
            String clientId = request.get("oauthClientId");
            String clientSecret = request.get("oauthClientSecret");
            String redirectUri = request.get("oauthRedirectUri");
            String authorizationUrl = request.get("oauthAuthorizationUrl");
            String tokenUrl = request.get("oauthTokenUrl");
            String userinfoUrl = request.get("oauthUserinfoUrl");

            TenantSsoConfig config = ssoConfigService.updateOauthConfig(
                    tenantId, oauthEnabled, clientId, clientSecret,
                    redirectUri, authorizationUrl, tokenUrl, userinfoUrl
            );

            // Validate configuration if enabled
            if (oauthEnabled) {
                if (!ssoConfigService.validateOauthConfig(config)) {
                    response.put("success", false);
                    response.put("message", "Invalid OAuth configuration. Please check all required fields.");
                    return ResponseEntity.badRequest().body(response);
                }
            }

            response.put("success", true);
            response.put("message", "OAuth configuration saved successfully");
            response.put("data", config);

            System.out.println("✅ OAuth config saved for tenant ID: " + tenantId);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            e.printStackTrace();
            response.put("success", false);
            response.put("message", "Failed to save OAuth configuration: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    /**
     * Save JWT configuration
     */
    @PostMapping("/save-jwt")
    public ResponseEntity<Map<String, Object>> saveJwtConfig(@RequestBody Map<String, String> request) {
        Map<String, Object> response = new HashMap<>();

        try {
            Long tenantId = TenantContext.getTenantId();
            if (tenantId == null) {
                response.put("success", false);
                response.put("message", "No tenant context found");
                return ResponseEntity.badRequest().body(response);
            }

            Boolean jwtEnabled = Boolean.parseBoolean(request.get("jwtEnabled"));
            String loginUrl = request.get("miniorangeLoginUrl");
            String clientId = request.get("miniorangeClientId");
            String clientSecret = request.get("miniorangeClientSecret");
            String redirectUri = request.get("miniorangeRedirectUri");

            TenantSsoConfig config = ssoConfigService.updateJwtConfig(
                    tenantId, jwtEnabled, loginUrl, clientId, clientSecret, redirectUri
            );

            // Validate configuration if enabled
            if (jwtEnabled) {
                if (!ssoConfigService.validateJwtConfig(config)) {
                    response.put("success", false);
                    response.put("message", "Invalid JWT configuration. Please check all required fields.");
                    return ResponseEntity.badRequest().body(response);
                }
            }

            response.put("success", true);
            response.put("message", "JWT configuration saved successfully");
            response.put("data", config);

            System.out.println("✅ JWT config saved for tenant ID: " + tenantId);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            e.printStackTrace();
            response.put("success", false);
            response.put("message", "Failed to save JWT configuration: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    /**
     * Get current SSO configuration
     */
    @GetMapping("/config")
    public ResponseEntity<Map<String, Object>> getSsoConfig() {
        Map<String, Object> response = new HashMap<>();

        try {
            Long tenantId = TenantContext.getTenantId();
            if (tenantId == null) {
                response.put("success", false);
                response.put("message", "No tenant context found");
                return ResponseEntity.badRequest().body(response);
            }

            TenantSsoConfig config = ssoConfigService.getOrCreateSsoConfig(tenantId);

            response.put("success", true);
            response.put("data", config);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            e.printStackTrace();
            response.put("success", false);
            response.put("message", "Failed to retrieve SSO configuration: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    /**
     * Check SSO status for tenant
     */
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getSsoStatus() {
        Map<String, Object> response = new HashMap<>();

        try {
            Long tenantId = TenantContext.getTenantId();
            if (tenantId == null) {
                response.put("success", false);
                response.put("message", "No tenant context found");
                return ResponseEntity.badRequest().body(response);
            }

            Map<String, Boolean> status = new HashMap<>();
            status.put("samlEnabled", ssoConfigService.isSamlEnabled(tenantId));
            status.put("oauthEnabled", ssoConfigService.isOauthEnabled(tenantId));
            status.put("jwtEnabled", ssoConfigService.isJwtEnabled(tenantId));
            status.put("anySsoEnabled", ssoConfigService.isAnySsoEnabled(tenantId));

            response.put("success", true);
            response.put("data", status);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            e.printStackTrace();
            response.put("success", false);
            response.put("message", "Failed to retrieve SSO status: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }
}