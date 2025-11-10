package com.example.darkknight.controller;

import com.example.darkknight.model.Tenant;
import com.example.darkknight.model.TenantSsoConfig;
import com.example.darkknight.repository.TenantRepository;
import com.example.darkknight.service.TenantSsoConfigService;
import com.example.darkknight.util.TenantContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Optional;

/**
 * Controller for displaying the login page with dynamic SSO options
 * based on tenant configuration
 */
@Controller
public class CustomLoginController {

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private TenantSsoConfigService ssoConfigService;

    /**
     * Display login page with tenant-specific SSO options
     * This method ONLY handles GET requests - form submission is handled by AuthController
     */
    @GetMapping("/login")
    public String showLoginPage(Model model) {
        Long tenantId = TenantContext.getTenantId();
        String subdomain = TenantContext.getSubdomain();

        System.out.println("🔐 Login page requested - Tenant ID: " + tenantId + ", Subdomain: " + subdomain);

        // Default values (no tenant)
        boolean samlEnabled = false;
        boolean oauthEnabled = false;
        boolean jwtEnabled = false;
        String tenantName = "Application";
        TenantSsoConfig ssoConfig = null;

        // If accessing via tenant subdomain, load tenant-specific config
        if (tenantId != null) {
            Optional<Tenant> tenantOpt = tenantRepository.findById(tenantId);

            if (tenantOpt.isPresent()) {
                Tenant tenant = tenantOpt.get();
                tenantName = tenant.getName();

                System.out.println("✅ Tenant found: " + tenantName + " (ID: " + tenantId + ")");

                // Get SSO configuration for this tenant
                Optional<TenantSsoConfig> configOpt = ssoConfigService.getSsoConfigByTenantId(tenantId);

                if (configOpt.isPresent()) {
                    ssoConfig = configOpt.get();
                    samlEnabled = Boolean.TRUE.equals(ssoConfig.getSamlEnabled());
                    oauthEnabled = Boolean.TRUE.equals(ssoConfig.getOauthEnabled());
                    jwtEnabled = Boolean.TRUE.equals(ssoConfig.getJwtEnabled());

                    System.out.println("🔧 SSO Config - SAML: " + samlEnabled +
                            ", OAuth: " + oauthEnabled +
                            ", JWT: " + jwtEnabled);
                } else {
                    System.out.println("⚠️ No SSO config found for tenant: " + tenantId);
                }
            } else {
                System.out.println("⚠️ Tenant not found for ID: " + tenantId);
            }
        } else {
            System.out.println("ℹ️ No tenant context - displaying main login page");
        }

        // Add attributes to model for Thymeleaf template
        model.addAttribute("tenantName", tenantName);
        model.addAttribute("subdomain", subdomain);
        model.addAttribute("samlEnabled", samlEnabled);
        model.addAttribute("oauthEnabled", oauthEnabled);
        model.addAttribute("jwtEnabled", jwtEnabled);
        model.addAttribute("anySsoEnabled", samlEnabled || oauthEnabled || jwtEnabled);

        // Add SSO config object (can be null)
        if (ssoConfig != null) {
            model.addAttribute("ssoConfig", ssoConfig);
        }

        System.out.println("🎨 Rendering login page with SSO options: " +
                (samlEnabled || oauthEnabled || jwtEnabled ? "Yes" : "No"));

        return "login";
    }

    // NOTE: This controller does NOT handle:
    // - POST /login (handled by AuthController)
    // - GET /dashboard (handled by AuthController)
    // - Any SSO login endpoints (handled by SAMLController, OAuthController, JwtSsoController)
}