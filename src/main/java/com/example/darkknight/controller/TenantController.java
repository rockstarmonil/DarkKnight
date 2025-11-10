package com.example.darkknight.controller;

import com.example.darkknight.model.Tenant;
import com.example.darkknight.model.User;
import com.example.darkknight.repository.TenantRepository;
import com.example.darkknight.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Controller
@RequestMapping("/tenant")
public class TenantController {

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Value("${app.domain:localhost}")
    private String appDomain;

    @Value("${app.environment:development}")
    private String environment;

    @Value("${app.protocol:http}")
    private String protocol;

    @Value("${app.port:8080}")
    private String port;

    /**
     * Show tenant registration page
     */
    @GetMapping("/register")
    public String showRegistrationPage(Model model, HttpServletRequest request) {
        model.addAttribute("environment", environment);
        model.addAttribute("previewDomain", getPreviewDomain(request));

        System.out.println("📝 Tenant registration page requested");
        System.out.println("🌍 Environment: " + environment);
        System.out.println("🔗 Preview domain: " + getPreviewDomain(request));

        return "tenant-register";
    }

    /**
     * Register a new tenant
     */
    @PostMapping("/register")
    @ResponseBody
    public Map<String, Object> registerTenant(@RequestBody Map<String, String> request,
                                              HttpServletRequest httpRequest) {
        Map<String, Object> response = new HashMap<>();

        try {
            String subdomain = request.get("subdomain").toLowerCase().trim();
            String companyName = request.get("companyName").trim();
            String adminEmail = request.get("adminEmail").trim();
            String adminPassword = request.get("adminPassword");

            System.out.println("🏢 Tenant registration attempt:");
            System.out.println("   Company: " + companyName);
            System.out.println("   Subdomain: " + subdomain);
            System.out.println("   Admin Email: " + adminEmail);

            // Validate subdomain format
            if (!subdomain.matches("^[a-z0-9-]{3,63}$")) {
                response.put("success", false);
                response.put("message", "Invalid subdomain format. Use only lowercase letters, numbers, and hyphens (3-63 chars)");
                return response;
            }

            // Check if subdomain already exists
            if (tenantRepository.findBySubdomain(subdomain).isPresent()) {
                response.put("success", false);
                response.put("message", "Subdomain already exists. Please choose another one.");
                return response;
            }

            // Check if admin email already exists
            if (userRepository.findByEmail(adminEmail).isPresent()) {
                response.put("success", false);
                response.put("message", "Email already registered. Please use a different email.");
                return response;
            }

            // Create tenant
            Tenant tenant = new Tenant();
            tenant.setName(companyName);
            tenant.setSubdomain(subdomain);
            tenant.setStatus("active");
            tenant.setMaxUsers(50); // Default max users
            tenant.setCreatedAt(LocalDateTime.now());
            tenant.setUpdatedAt(LocalDateTime.now());

            // Save tenant first to get ID
            tenant = tenantRepository.save(tenant);
            System.out.println("✅ Tenant created: " + tenant.getName() + " (ID: " + tenant.getId() + ")");

            // Create admin user
            User admin = new User();
            admin.setEmail(adminEmail);
            admin.setUsername(adminEmail);
            admin.setPassword(passwordEncoder.encode(adminPassword));
            admin.setRole("ROLE_ADMIN");
            admin.setEnabled(true);
            admin.setTenant(tenant);
            admin.setCreatedAt(LocalDateTime.now());
            admin.setUpdatedAt(LocalDateTime.now());

            userRepository.save(admin);
            System.out.println("✅ Admin user created: " + admin.getEmail());

            // Update tenant with owner reference
            tenant.setOwner(admin);
            tenantRepository.save(tenant);

            // Build login URL based on environment
            String loginUrl = buildLoginUrl(subdomain, httpRequest);
            System.out.println("🔗 Login URL: " + loginUrl);

            response.put("success", true);
            response.put("message", "Tenant created successfully!");
            response.put("tenantId", tenant.getId());
            response.put("subdomain", subdomain);
            response.put("loginUrl", loginUrl);

        } catch (Exception e) {
            System.err.println("❌ Tenant registration failed: " + e.getMessage());
            e.printStackTrace();
            response.put("success", false);
            response.put("message", "Registration failed: " + e.getMessage());
        }

        return response;
    }

    /**
     * Check if subdomain is available
     */
    @GetMapping("/check-subdomain")
    @ResponseBody
    public Map<String, Boolean> checkSubdomainAvailability(@RequestParam String subdomain) {
        Map<String, Boolean> response = new HashMap<>();

        subdomain = subdomain.toLowerCase().trim();

        // Check format
        if (!subdomain.matches("^[a-z0-9-]{3,63}$")) {
            response.put("available", false);
            return response;
        }

        // Check if exists in database
        boolean available = tenantRepository.findBySubdomain(subdomain).isEmpty();
        response.put("available", available);

        System.out.println("🔍 Subdomain check: " + subdomain + " -> " + (available ? "Available" : "Taken"));

        return response;
    }

    /**
     * Build the correct login URL based on environment
     */
    private String buildLoginUrl(String subdomain, HttpServletRequest request) {
        // Development (localhost)
        if ("development".equalsIgnoreCase(environment) || "localhost".equals(appDomain)) {
            return protocol + "://" + subdomain + ".localhost:" + port + "/login";
        }

        // Production
        // For production, use the actual domain from the request or configured domain
        String scheme = request.getScheme(); // http or https
        String domain = appDomain;

        // If using standard ports (80 for http, 443 for https), don't include port
        boolean isStandardPort =
                ("http".equals(scheme) && "80".equals(port)) ||
                        ("https".equals(scheme) && "443".equals(port));

        if (isStandardPort) {
            return scheme + "://" + subdomain + "." + domain + "/login";
        } else {
            return scheme + "://" + subdomain + "." + domain + ":" + port + "/login";
        }
    }

    /**
     * Get preview domain for the registration form
     */
    private String getPreviewDomain(HttpServletRequest request) {
        // Development
        if ("development".equalsIgnoreCase(environment) || "localhost".equals(appDomain)) {
            return "localhost:" + port;
        }

        // Production
        String scheme = request.getScheme();
        boolean isStandardPort =
                ("http".equals(scheme) && "80".equals(port)) ||
                        ("https".equals(scheme) && "443".equals(port));

        if (isStandardPort) {
            return appDomain;
        } else {
            return appDomain + ":" + port;
        }
    }
}