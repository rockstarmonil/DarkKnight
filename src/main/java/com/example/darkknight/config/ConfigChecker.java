package com.example.darkknight.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

/**
 * Startup configuration checker
 * Displays current environment configuration on startup
 */
@Component
public class ConfigChecker implements CommandLineRunner {

    @Value("${app.environment:NOT_SET}")
    private String environment;

    @Value("${app.domain:NOT_SET}")
    private String domain;

    @Value("${app.protocol:NOT_SET}")
    private String protocol;

    @Value("${app.port:NOT_SET}")
    private String port;

    @Value("${spring.datasource.url:NOT_SET}")
    private String datasourceUrl;

    @Override
    public void run(String... args) {
        System.out.println("\n" +
                "╔═══════════════════════════════════════════════════════════════╗\n" +
                "║         DARKKNIGHT MULTI-TENANT APPLICATION                   ║\n" +
                "║                 CONFIGURATION CHECK                           ║\n" +
                "╚═══════════════════════════════════════════════════════════════╝\n");

        System.out.println("📋 ENVIRONMENT CONFIGURATION:");
        System.out.println("   ├─ Environment: " + environment);
        System.out.println("   ├─ Domain: " + domain);
        System.out.println("   ├─ Protocol: " + protocol);
        System.out.println("   └─ Port: " + port);

        System.out.println("\n🌐 GENERATED URLS:");
        String mainUrl = buildUrl("");
        String exampleTenantUrl = buildUrl("acme");

        System.out.println("   ├─ Main Domain: " + mainUrl);
        System.out.println("   └─ Example Tenant: " + exampleTenantUrl);

        System.out.println("\n💾 DATABASE:");
        System.out.println("   └─ URL: " + datasourceUrl);

        // Validation checks
        System.out.println("\n✅ VALIDATION CHECKS:");

        boolean allValid = true;

        if ("NOT_SET".equals(environment)) {
            System.out.println("   ❌ app.environment is NOT SET");
            allValid = false;
        } else if ("production".equalsIgnoreCase(environment) && "localhost".equals(domain)) {
            System.out.println("   ⚠️  WARNING: Environment is 'production' but domain is 'localhost'");
            System.out.println("      → Update app.domain to your actual domain (e.g., mycompany.com)");
            allValid = false;
        } else {
            System.out.println("   ✓ Environment configuration looks good");
        }

        if ("NOT_SET".equals(domain)) {
            System.out.println("   ❌ app.domain is NOT SET");
            allValid = false;
        }

        if ("NOT_SET".equals(protocol)) {
            System.out.println("   ❌ app.protocol is NOT SET");
            allValid = false;
        } else if ("production".equalsIgnoreCase(environment) && "http".equals(protocol)) {
            System.out.println("   ⚠️  WARNING: Production environment should use HTTPS");
            System.out.println("      → Update app.protocol=https");
        }

        if ("NOT_SET".equals(port)) {
            System.out.println("   ❌ app.port is NOT SET");
            allValid = false;
        }

        if (allValid) {
            System.out.println("\n🎉 CONFIGURATION VALID - Ready to go!");
        } else {
            System.out.println("\n⚠️  CONFIGURATION ISSUES DETECTED");
            System.out.println("   Please update application.properties and restart");
        }

        System.out.println("\n" +
                "═══════════════════════════════════════════════════════════════\n");
    }

    private String buildUrl(String subdomain) {
        StringBuilder url = new StringBuilder(protocol);
        url.append("://");

        if (subdomain != null && !subdomain.isEmpty()) {
            url.append(subdomain).append(".");
        }

        url.append(domain);

        // Add port if not standard
        boolean isStandardPort =
                ("http".equals(protocol) && "80".equals(port)) ||
                        ("https".equals(protocol) && "443".equals(port));

        if (!isStandardPort && !"NOT_SET".equals(port)) {
            url.append(":").append(port);
        }

        return url.toString();
    }
}