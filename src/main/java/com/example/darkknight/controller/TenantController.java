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

    @Value("${server.port:8080}")
    private String serverPort;

    /**
     * Show tenant registration page
     */
    @GetMapping("/register")
    public String showRegistrationPage(Model model) {
        model.addAttribute("appDomain", appDomain);
        model.addAttribute("environment", environment);
        model.addAttribute("previewDomain", getPreviewDomain());
        return "tenant-register";
    }

    /**
     * Handle tenant self-registration
     */
    @PostMapping("/register")
    @ResponseBody
    public Map<String, Object> registerTenant(@RequestBody Map<String, String> request) {
        Map<String, Object> response = new HashMap<>();

        try {
            String subdomain = request.get("subdomain").toLowerCase().trim();
            String companyName = request.get("companyName").trim();
            String adminEmail = request.get("adminEmail").trim();
            String adminPassword = request.get("adminPassword");

            // Validation
            if (subdomain.isEmpty() || companyName.isEmpty() || adminEmail.isEmpty() || adminPassword.isEmpty()) {
                response.put("success", false);
                response.put("message", "All fields are required");
                return response;
            }

            // Check subdomain format (alphanumeric and hyphens only)
            if (!subdomain.matches("^[a-z0-9-]+$")) {
                response.put("success", false);
                response.put("message", "Subdomain can only contain lowercase letters, numbers, and hyphens");
                return response;
            }

            // Check subdomain length
            if (subdomain.length() < 3 || subdomain.length() > 63) {
                response.put("success", false);
                response.put("message", "Subdomain must be between 3 and 63 characters");
                return response;
            }

            // Reserved subdomains
            String[] reservedSubdomains = {"www", "admin", "api", "mail", "ftp", "localhost",
                    "smtp", "pop", "imap", "webmail", "cpanel", "whm",
                    "staging", "dev", "test", "demo", "app", "portal"};
            for (String reserved : reservedSubdomains) {
                if (subdomain.equals(reserved)) {
                    response.put("success", false);
                    response.put("message", "This subdomain is reserved");
                    return response;
                }
            }

            // Check if subdomain already exists
            if (tenantRepository.existsBySubdomain(subdomain)) {
                response.put("success", false);
                response.put("message", "Subdomain already taken");
                return response;
            }

            // Check if email already exists
            if (userRepository.existsByEmail(adminEmail)) {
                response.put("success", false);
                response.put("message", "Email already registered");
                return response;
            }

            // Create tenant WITHOUT owner first
            Tenant tenant = new Tenant();
            tenant.setName(companyName);
            tenant.setSubdomain(subdomain);
            tenant.setStatus("ACTIVE");
            tenant.setMaxUsers(20);
            tenant.setCreatedAt(LocalDateTime.now());
            tenant.setUpdatedAt(LocalDateTime.now());

            // Save tenant first to get ID
            tenant = tenantRepository.save(tenant);

            // Create tenant admin user
            User admin = new User();
            admin.setEmail(adminEmail);
            admin.setUsername(adminEmail);
            admin.setPassword(passwordEncoder.encode(adminPassword));
            admin.setRole("ROLE_ADMIN");
            admin.setEnabled(true);
            admin.setCreatedAt(LocalDateTime.now());
            admin.setUpdatedAt(LocalDateTime.now());
            admin.setTenant(tenant);

            // Save admin user
            admin = userRepository.save(admin);

            // Update tenant with owner
            tenant.setOwner(admin);
            tenantRepository.save(tenant);

            System.out.println("✅ New tenant registered: " + subdomain);

            // Build login URL based on environment
            String loginUrl = buildTenantUrl(subdomain, "/login");

            response.put("success", true);
            response.put("message", "Tenant registered successfully!");
            response.put("subdomain", subdomain);
            response.put("loginUrl", loginUrl);

            return response;

        } catch (Exception e) {
            e.printStackTrace();
            response.put("success", false);
            response.put("message", "Registration failed: " + e.getMessage());
            return response;
        }
    }

    /**
     * Check if subdomain is available
     */
    @GetMapping("/check-subdomain")
    @ResponseBody
    public Map<String, Object> checkSubdomain(@RequestParam String subdomain) {
        Map<String, Object> response = new HashMap<>();
        subdomain = subdomain.toLowerCase().trim();

        boolean available = !tenantRepository.existsBySubdomain(subdomain);
        response.put("available", available);
        response.put("previewUrl", buildTenantUrl(subdomain, ""));

        return response;
    }

    /**
     * Build tenant URL based on environment
     * Development: http://subdomain.localhost:8080/path
     * Production: https://subdomain.yourdomain.com/path
     */
    private String buildTenantUrl(String subdomain, String path) {
        StringBuilder url = new StringBuilder();

        if ("development".equalsIgnoreCase(environment) || "localhost".equals(appDomain)) {
            // Development mode
            url.append("http://");
            url.append(subdomain);
            url.append(".localhost");
            if (!"80".equals(serverPort) && !"443".equals(serverPort)) {
                url.append(":").append(serverPort);
            }
        } else {
            // Production mode - use HTTPS
            url.append("https://");
            url.append(subdomain);
            url.append(".");
            url.append(appDomain);
        }

        url.append(path);
        return url.toString();
    }

    /**
     * Get preview domain for registration page
     */
    private String getPreviewDomain() {
        if ("development".equalsIgnoreCase(environment) || "localhost".equals(appDomain)) {
            return "localhost" + (!"80".equals(serverPort) && !"443".equals(serverPort) ? ":" + serverPort : "");
        } else {
            return appDomain;
        }
    }
}