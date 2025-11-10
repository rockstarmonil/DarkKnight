package com.example.darkknight.controller;

import com.example.darkknight.model.Tenant;
import com.example.darkknight.model.TenantSsoConfig;
import com.example.darkknight.model.User;
import com.example.darkknight.repository.TenantRepository;
import com.example.darkknight.repository.UserRepository;
import com.example.darkknight.service.TenantSsoConfigService;
import com.example.darkknight.util.TenantContext;
import org.springframework.beans.factory.annotation.Autowired;
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

    /**
     * Display tenant admin dashboard
     */
    @GetMapping("/dashboard")
    public String showDashboard(Authentication authentication, Model model) {
        // Get current tenant from context
        Long tenantId = TenantContext.getTenantId();
        if (tenantId == null) {
            return "redirect:/error?message=No+tenant+context";
        }

        // Get tenant
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new RuntimeException("Tenant not found"));

        // Get current admin user
        String username = authentication.getName();
        User admin = userRepository.findByEmail(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Check if user is admin
        if (!admin.getRole().equals("ROLE_ADMIN")) {
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

        // Add attributes to model
        model.addAttribute("tenant", tenant);
        model.addAttribute("admin", admin);
        model.addAttribute("users", users);
        model.addAttribute("totalUsers", totalUsers);
        model.addAttribute("activeUsers", activeUsers);
        model.addAttribute("availableSlots", availableSlots);
        model.addAttribute("ssoConfig", ssoConfig);

        return "tenant-admin-dashboard";
    }

    /**
     * Redirect to dashboard from base path
     */
    @GetMapping
    public String redirectToDashboard() {
        return "redirect:/tenant-admin/dashboard";
    }
}