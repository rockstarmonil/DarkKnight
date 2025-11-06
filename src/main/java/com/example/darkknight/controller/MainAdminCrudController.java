package com.example.darkknight.controller;

import com.example.darkknight.model.Tenant;
import com.example.darkknight.model.User;
import com.example.darkknight.repository.TenantRepository;
import com.example.darkknight.repository.UserRepository;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
@RequestMapping("/main-admin")
public class MainAdminCrudController {

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    // ========================
    // TENANT CRUD OPERATIONS
    // ========================

    /**
     * Create new tenant (Main Admin only)
     */
    @PostMapping("/tenants/create")
    @ResponseBody
    public Map<String, Object> createTenant(@RequestBody Map<String, String> request, HttpSession session) {
        Map<String, Object> response = new HashMap<>();

        try {
            // Verify super admin
            if (session.getAttribute("superAdmin") == null) {
                response.put("success", false);
                response.put("message", "Unauthorized");
                return response;
            }

            String companyName = request.get("companyName");
            String subdomain = request.get("subdomain").toLowerCase().trim();
            String adminEmail = request.get("adminEmail");
            String adminPassword = request.get("adminPassword");
            Integer maxUsers = Integer.parseInt(request.getOrDefault("maxUsers", "20"));

            // Validation
            if (tenantRepository.existsBySubdomain(subdomain)) {
                response.put("success", false);
                response.put("message", "Subdomain already exists");
                return response;
            }

            if (userRepository.existsByEmail(adminEmail)) {
                response.put("success", false);
                response.put("message", "Email already registered");
                return response;
            }

            // Create tenant
            Tenant tenant = new Tenant();
            tenant.setName(companyName);
            tenant.setSubdomain(subdomain);
            tenant.setStatus("ACTIVE");
            tenant.setMaxUsers(maxUsers);
            tenant.setCreatedAt(LocalDateTime.now());
            tenant.setUpdatedAt(LocalDateTime.now());
            tenant = tenantRepository.save(tenant);

            // Create admin user
            User admin = new User();
            admin.setEmail(adminEmail);
            admin.setUsername(adminEmail);
            admin.setPassword(passwordEncoder.encode(adminPassword));
            admin.setRole("ROLE_ADMIN");
            admin.setEnabled(true);
            admin.setTenant(tenant);
            admin = userRepository.save(admin);

            // Update tenant with owner
            tenant.setOwner(admin);
            tenantRepository.save(tenant);

            response.put("success", true);
            response.put("message", "Tenant created successfully");
            response.put("tenantId", tenant.getId());

        } catch (Exception e) {
            e.printStackTrace();
            response.put("success", false);
            response.put("message", "Error: " + e.getMessage());
        }

        return response;
    }

    /**
     * Update tenant details
     */
    @PostMapping("/tenants/update")
    @ResponseBody
    public Map<String, Object> updateTenant(@RequestBody Map<String, String> request, HttpSession session) {
        Map<String, Object> response = new HashMap<>();

        try {
            if (session.getAttribute("superAdmin") == null) {
                response.put("success", false);
                response.put("message", "Unauthorized");
                return response;
            }

            Long tenantId = Long.parseLong(request.get("tenantId"));
            Tenant tenant = tenantRepository.findById(tenantId)
                    .orElseThrow(() -> new RuntimeException("Tenant not found"));

            if (request.containsKey("name")) {
                tenant.setName(request.get("name"));
            }
            if (request.containsKey("maxUsers")) {
                tenant.setMaxUsers(Integer.parseInt(request.get("maxUsers")));
            }
            if (request.containsKey("status")) {
                tenant.setStatus(request.get("status"));
            }

            tenant.setUpdatedAt(LocalDateTime.now());
            tenantRepository.save(tenant);

            response.put("success", true);
            response.put("message", "Tenant updated successfully");

        } catch (Exception e) {
            e.printStackTrace();
            response.put("success", false);
            response.put("message", "Error: " + e.getMessage());
        }

        return response;
    }

    /**
     * Toggle tenant status (ACTIVE/SUSPENDED)
     */
    @PostMapping("/tenants/{id}/toggle-status")
    @ResponseBody
    public Map<String, Object> toggleTenantStatus(@PathVariable Long id, HttpSession session) {
        Map<String, Object> response = new HashMap<>();

        try {
            if (session.getAttribute("superAdmin") == null) {
                response.put("success", false);
                response.put("message", "Unauthorized");
                return response;
            }

            Tenant tenant = tenantRepository.findById(id)
                    .orElseThrow(() -> new RuntimeException("Tenant not found"));

            String newStatus = tenant.isActive() ? "SUSPENDED" : "ACTIVE";
            tenant.setStatus(newStatus);
            tenant.setUpdatedAt(LocalDateTime.now());
            tenantRepository.save(tenant);

            response.put("success", true);
            response.put("message", "Tenant status changed to: " + newStatus);
            response.put("newStatus", newStatus);

        } catch (Exception e) {
            e.printStackTrace();
            response.put("success", false);
            response.put("message", "Error: " + e.getMessage());
        }

        return response;
    }

    /**
     * Delete tenant (with all users)
     */
    @DeleteMapping("/tenants/{id}")
    @ResponseBody
    public Map<String, Object> deleteTenant(@PathVariable Long id, HttpSession session) {
        Map<String, Object> response = new HashMap<>();

        try {
            if (session.getAttribute("superAdmin") == null) {
                response.put("success", false);
                response.put("message", "Unauthorized");
                return response;
            }

            Tenant tenant = tenantRepository.findById(id)
                    .orElseThrow(() -> new RuntimeException("Tenant not found"));

            // Delete all users first (cascade should handle this, but being explicit)
            List<User> tenantUsers = userRepository.findByTenantId(id);
            userRepository.deleteAll(tenantUsers);

            // Delete tenant
            tenantRepository.delete(tenant);

            response.put("success", true);
            response.put("message", "Tenant and all users deleted successfully");

        } catch (Exception e) {
            e.printStackTrace();
            response.put("success", false);
            response.put("message", "Error: " + e.getMessage());
        }

        return response;
    }

    // ========================
    // USER CRUD OPERATIONS (Main Admin)
    // ========================

    /**
     * Update user details (Main Admin)
     */
    @PostMapping("/users/update")
    @ResponseBody
    public Map<String, Object> updateUser(@RequestBody Map<String, String> request, HttpSession session) {
        Map<String, Object> response = new HashMap<>();

        try {
            if (session.getAttribute("superAdmin") == null) {
                response.put("success", false);
                response.put("message", "Unauthorized");
                return response;
            }

            Long userId = Long.parseLong(request.get("userId"));
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            if (request.containsKey("firstName")) {
                user.setFirstName(request.get("firstName"));
            }
            if (request.containsKey("lastName")) {
                user.setLastName(request.get("lastName"));
            }
            if (request.containsKey("email")) {
                user.setEmail(request.get("email"));
            }
            if (request.containsKey("role")) {
                user.setRole(request.get("role"));
            }

            user.setUpdatedAt(LocalDateTime.now());
            userRepository.save(user);

            response.put("success", true);
            response.put("message", "User updated successfully");

        } catch (Exception e) {
            e.printStackTrace();
            response.put("success", false);
            response.put("message", "Error: " + e.getMessage());
        }

        return response;
    }

    /**
     * Toggle user enabled status
     */
    @PostMapping("/users/{id}/toggle-status")
    @ResponseBody
    public Map<String, Object> toggleUserStatus(@PathVariable Long id, HttpSession session) {
        Map<String, Object> response = new HashMap<>();

        try {
            if (session.getAttribute("superAdmin") == null) {
                response.put("success", false);
                response.put("message", "Unauthorized");
                return response;
            }

            User user = userRepository.findById(id)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            user.setEnabled(!user.isEnabled());
            user.setUpdatedAt(LocalDateTime.now());
            userRepository.save(user);

            response.put("success", true);
            response.put("message", "User status updated");
            response.put("enabled", user.isEnabled());

        } catch (Exception e) {
            e.printStackTrace();
            response.put("success", false);
            response.put("message", "Error: " + e.getMessage());
        }

        return response;
    }

    /**
     * Delete user
     */
    @DeleteMapping("/users/{id}")
    @ResponseBody
    public Map<String, Object> deleteUser(@PathVariable Long id, HttpSession session) {
        Map<String, Object> response = new HashMap<>();

        try {
            if (session.getAttribute("superAdmin") == null) {
                response.put("success", false);
                response.put("message", "Unauthorized");
                return response;
            }

            User user = userRepository.findById(id)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Check if user is a tenant owner
            if (user.getTenant() != null && user.getTenant().getOwner() != null
                    && user.getTenant().getOwner().getId().equals(id)) {
                response.put("success", false);
                response.put("message", "Cannot delete tenant owner");
                return response;
            }

            userRepository.delete(user);

            response.put("success", true);
            response.put("message", "User deleted successfully");

        } catch (Exception e) {
            e.printStackTrace();
            response.put("success", false);
            response.put("message", "Error: " + e.getMessage());
        }

        return response;
    }
}