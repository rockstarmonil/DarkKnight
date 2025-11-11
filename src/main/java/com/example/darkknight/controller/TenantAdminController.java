package com.example.darkknight.controller;

import com.example.darkknight.model.Tenant;
import com.example.darkknight.model.TenantSsoConfig;
import com.example.darkknight.model.User;
import com.example.darkknight.repository.TenantRepository;
import com.example.darkknight.repository.UserRepository;
import com.example.darkknight.service.TenantSsoConfigService;
import com.example.darkknight.util.TenantContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.List;

@Controller
@RequestMapping("/tenant-admin")
public class TenantAdminController {

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TenantSsoConfigService ssoConfigService;

    @Value("${app.domain:localhost}")
    private String appDomain;

    @Value("${app.environment:development}")
    private String environment;

    @Value("${app.protocol:http}")
    private String protocol;

    @Value("${app.port:8080}")
    private String port;

    /**
     * Display tenant admin dashboard
     */
    @GetMapping("/dashboard")
    public String showDashboard(Authentication authentication, Model model) {
        // Get current tenant from context
        Long tenantId = TenantContext.getTenantId();
        String subdomain = TenantContext.getSubdomain();

        if (tenantId == null) {
            System.out.println("❌ No tenant context found");
            return "redirect:/error?message=No+tenant+context";
        }

        System.out.println("📊 Tenant Admin Dashboard - Tenant ID: " + tenantId + ", Subdomain: " + subdomain);

        // Get tenant
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new RuntimeException("Tenant not found"));

        // Get current admin user
        String username = authentication.getName();
        User admin = userRepository.findByEmail(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Check if user is admin
        if (!admin.getRole().equals("ROLE_ADMIN")) {
            System.out.println("❌ User is not admin: " + username);
            return "redirect:/error?message=Access+denied";
        }

        // Get all users for this tenant
        List<User> users = userRepository.findByTenantId(tenantId);

        // Calculate stats
        long totalUsers = users.size();
        long activeUsers = users.stream().filter(User::isEnabled).count();
        long availableSlots = tenant.getMaxUsers() - totalUsers;

        // Get or create SSO configuration
        TenantSsoConfig ssoConfig = ssoConfigService.getOrCreateSsoConfig(tenantId);

        // Build tenant URL
        String tenantUrl = buildTenantUrl(tenant.getSubdomain());

        // Add attributes to model
        model.addAttribute("tenant", tenant);
        model.addAttribute("admin", admin);
        model.addAttribute("users", users);
        model.addAttribute("totalUsers", totalUsers);
        model.addAttribute("activeUsers", activeUsers);
        model.addAttribute("availableSlots", availableSlots);
        model.addAttribute("ssoConfig", ssoConfig);
        model.addAttribute("tenantUrl", tenantUrl);
        model.addAttribute("subdomain", subdomain);
        model.addAttribute("environment", environment);

        System.out.println("✅ Tenant Admin Dashboard loaded");
        System.out.println("   - Tenant: " + tenant.getName());
        System.out.println("   - Admin: " + admin.getEmail());
        System.out.println("   - Total Users: " + totalUsers);
        System.out.println("   - Tenant URL: " + tenantUrl);

        return "tenant-admin-dashboard";
    }

    /**
     * Redirect to dashboard from base path
     */
    @GetMapping
    public String redirectToDashboard() {
        return "redirect:/tenant-admin/dashboard";
    }

    /**
     * Build the complete tenant URL for display
     */
    private String buildTenantUrl(String subdomain) {
        String url;

        // Development
        if ("development".equalsIgnoreCase(environment) || "localhost".equals(appDomain)) {
            url = protocol + "://" + subdomain + ".localhost:" + port;
        }
        // Production
        else {
            String baseUrl = protocol + "://" + subdomain + "." + appDomain;

            boolean isStandardPort =
                    ("http".equals(protocol) && "80".equals(port)) ||
                            ("https".equals(protocol) && "443".equals(port));

            if (isStandardPort) {
                url = baseUrl;
            } else {
                url = baseUrl + ":" + port;
            }
        }

        return url;
    }
}