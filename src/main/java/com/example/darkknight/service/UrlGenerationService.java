package com.example.darkknight.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

@Service
public class UrlGenerationService {

    @Value("${app.domain}")
    private String appDomain;

    @Value("${app.protocol:https}")
    private String protocol;

    @Value("${server.port:8080}")
    private String serverPort;

    /**
     * Generate tenant URL without port number
     */
    public String generateTenantUrl(String tenantSubdomain) {
        // Don't include port for standard ports (80 for HTTP, 443 for HTTPS)
        if (isProductionEnvironment()) {
            return String.format("%s://%s.%s", protocol, tenantSubdomain, appDomain);
        } else {
            // For local development, include port
            return String.format("%s://%s.%s:%s", protocol, tenantSubdomain, appDomain, serverPort);
        }
    }

    /**
     * Generate main domain URL
     */
    public String generateMainDomainUrl() {
        if (isProductionEnvironment()) {
            return String.format("%s://%s", protocol, appDomain);
        } else {
            return String.format("%s://%s:%s", protocol, appDomain, serverPort);
        }
    }

    /**
     * Generate full URL with path
     */
    public String generateUrlWithPath(String tenantSubdomain, String path) {
        String baseUrl = generateTenantUrl(tenantSubdomain);
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        return baseUrl + path;
    }

    /**
     * Check if running in production (no port in URL needed)
     */
    private boolean isProductionEnvironment() {
        // Standard HTTPS port (443) or HTTP port (80) - don't show in URL
        return "https".equals(protocol) || "80".equals(serverPort);
    }

    /**
     * Get current request base URL (for dynamic scenarios)
     */
    public String getCurrentBaseUrl() {
        try {
            return ServletUriComponentsBuilder.fromCurrentContextPath()
                    .build()
                    .toUriString();
        } catch (Exception e) {
            return generateMainDomainUrl();
        }
    }
}