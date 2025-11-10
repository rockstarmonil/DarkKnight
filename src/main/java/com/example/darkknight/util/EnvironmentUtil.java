package com.example.darkknight.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Utility class for environment-specific configurations and URL building
 */
@Component
public class EnvironmentUtil {

    @Value("${app.domain:localhost}")
    private String appDomain;

    @Value("${app.environment:development}")
    private String environment;

    @Value("${server.port:8080}")
    private String serverPort;

    @Value("${app.base.url:http://localhost:8080}")
    private String baseUrl;

    /**
     * Check if running in production environment
     */
    public boolean isProduction() {
        return "production".equalsIgnoreCase(environment);
    }

    /**
     * Check if running in development environment
     */
    public boolean isDevelopment() {
        return "development".equalsIgnoreCase(environment) || "localhost".equals(appDomain);
    }

    /**
     * Get the current environment name
     */
    public String getEnvironment() {
        return environment;
    }

    /**
     * Get the application domain
     */
    public String getAppDomain() {
        return appDomain;
    }

    /**
     * Get the base URL
     */
    public String getBaseUrl() {
        return baseUrl;
    }

    /**
     * Build a tenant-specific URL
     *
     * Development: http://subdomain.localhost:8080/path
     * Production: https://subdomain.yourdomain.com/path
     *
     * @param subdomain The tenant subdomain
     * @param path The path (e.g., "/login", "/dashboard")
     * @return Complete tenant URL
     */
    public String buildTenantUrl(String subdomain, String path) {
        if (subdomain == null || subdomain.isEmpty()) {
            return baseUrl + (path != null ? path : "");
        }

        StringBuilder url = new StringBuilder();

        if (isDevelopment()) {
            // Development mode
            url.append("http://");
            url.append(subdomain);
            url.append(".localhost");
            if (shouldIncludePort()) {
                url.append(":").append(serverPort);
            }
        } else {
            // Production mode - use HTTPS
            url.append("https://");
            url.append(subdomain);
            url.append(".");
            url.append(appDomain);
        }

        if (path != null && !path.isEmpty()) {
            if (!path.startsWith("/")) {
                url.append("/");
            }
            url.append(path);
        }

        return url.toString();
    }

    /**
     * Build a tenant-specific URL without path
     *
     * @param subdomain The tenant subdomain
     * @return Complete tenant URL
     */
    public String buildTenantUrl(String subdomain) {
        return buildTenantUrl(subdomain, "");
    }

    /**
     * Get preview domain for displaying in UI
     * Development: localhost:8080
     * Production: yourdomain.com
     */
    public String getPreviewDomain() {
        if (isDevelopment()) {
            return "localhost" + (shouldIncludePort() ? ":" + serverPort : "");
        } else {
            return appDomain;
        }
    }

    /**
     * Get full preview URL with subdomain placeholder
     * Development: subdomain.localhost:8080
     * Production: subdomain.yourdomain.com
     */
    public String getPreviewUrl(String placeholder) {
        if (placeholder == null || placeholder.isEmpty()) {
            placeholder = "yourcompany";
        }
        return placeholder + "." + getPreviewDomain();
    }

    /**
     * Get protocol based on environment
     */
    public String getProtocol() {
        return isProduction() ? "https" : "http";
    }

    /**
     * Check if port should be included in URLs
     */
    private boolean shouldIncludePort() {
        return !"80".equals(serverPort) && !"443".equals(serverPort);
    }

    /**
     * Extract subdomain from a full hostname
     *
     * @param hostname Full hostname (e.g., "acme.localhost" or "acme.yourdomain.com")
     * @return Subdomain or null if none
     */
    public String extractSubdomain(String hostname) {
        if (hostname == null || hostname.isEmpty()) {
            return null;
        }

        // Remove port if present
        if (hostname.contains(":")) {
            hostname = hostname.substring(0, hostname.indexOf(":"));
        }

        // Convert to lowercase
        hostname = hostname.toLowerCase();

        // Check if it's just the base domain
        if (hostname.equals(appDomain)) {
            return null;
        }

        // Split by dots
        String[] parts = hostname.split("\\.");

        // Development mode
        if (isDevelopment()) {
            if (parts.length >= 2 && "localhost".equals(parts[parts.length - 1])) {
                return parts[0];
            }
            if (parts.length == 1 && "localhost".equals(parts[0])) {
                return null;
            }
        }

        // Production mode
        String[] domainParts = appDomain.split("\\.");
        int domainPartCount = domainParts.length;

        if (parts.length > domainPartCount) {
            // Verify base domain matches
            boolean baseMatches = true;
            for (int i = 0; i < domainPartCount; i++) {
                if (!parts[parts.length - domainPartCount + i].equals(domainParts[i])) {
                    baseMatches = false;
                    break;
                }
            }

            if (baseMatches) {
                return parts[0];
            }
        }

        return null;
    }

    /**
     * Validate subdomain format
     *
     * @param subdomain Subdomain to validate
     * @return true if valid, false otherwise
     */
    public boolean isValidSubdomain(String subdomain) {
        if (subdomain == null || subdomain.isEmpty()) {
            return false;
        }

        // Check length
        if (subdomain.length() < 3 || subdomain.length() > 63) {
            return false;
        }

        // Check format (alphanumeric and hyphens only)
        if (!subdomain.matches("^[a-z0-9-]+$")) {
            return false;
        }

        // Cannot start or end with hyphen
        if (subdomain.startsWith("-") || subdomain.endsWith("-")) {
            return false;
        }

        // Check against reserved subdomains
        String[] reserved = {"www", "admin", "api", "mail", "ftp", "localhost",
                "smtp", "pop", "imap", "webmail", "cpanel", "whm",
                "staging", "dev", "test", "demo", "app", "portal"};

        for (String r : reserved) {
            if (subdomain.equals(r)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Get environment-specific configuration info for debugging
     */
    public String getConfigInfo() {
        return String.format(
                "Environment: %s | Domain: %s | Base URL: %s | Protocol: %s",
                environment, appDomain, baseUrl, getProtocol()
        );
    }
}