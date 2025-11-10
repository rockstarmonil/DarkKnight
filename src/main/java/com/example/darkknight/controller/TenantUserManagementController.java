package com.example.darkknight.controller;

import com.example.darkknight.model.Tenant;
import com.example.darkknight.model.User;
import com.example.darkknight.repository.TenantRepository;
import com.example.darkknight.repository.UserRepository;
import com.example.darkknight.util.TenantContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/tenant-admin/users")
@PreAuthorize("hasRole('ADMIN')")
public class TenantUserManagementController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * Create a new user for the tenant
     */
    @PostMapping("/create")
    public ResponseEntity<Map<String, Object>> createUser(@RequestBody Map<String, String> request) {
        Map<String, Object> response = new HashMap<>();

        try {
            Long tenantId = TenantContext.getTenantId();
            if (tenantId == null) {
                response.put("success", false);
                response.put("message", "No tenant context found");
                return ResponseEntity.badRequest().body(response);
            }

            // Get tenant and check user limit
            Tenant tenant = tenantRepository.findById(tenantId)
                    .orElseThrow(() -> new RuntimeException("Tenant not found"));

            long currentUsers = userRepository.countByTenantId(tenantId);
            if (currentUsers >= tenant.getMaxUsers()) {
                response.put("success", false);
                response.put("message", "User limit reached. Maximum " + tenant.getMaxUsers() + " users allowed.");
                return ResponseEntity.badRequest().body(response);
            }

            String email = request.get("email");
            String password = request.get("password");
            String firstName = request.get("firstName");
            String lastName = request.get("lastName");
            String role = request.get("role");

            // Validation
            if (email == null || email.isEmpty() || password == null || password.isEmpty()) {
                response.put("success", false);
                response.put("message", "Email and password are required");
                return ResponseEntity.badRequest().body(response);
            }

            if (password.length() < 6) {
                response.put("success", false);
                response.put("message", "Password must be at least 6 characters");
                return ResponseEntity.badRequest().body(response);
            }

            // Check if email already exists
            if (userRepository.existsByEmail(email)) {
                response.put("success", false);
                response.put("message", "Email already exists");
                return ResponseEntity.badRequest().body(response);
            }

            // Create new user
            User newUser = new User();
            newUser.setEmail(email);
            newUser.setUsername(email);
            newUser.setPassword(passwordEncoder.encode(password));
            newUser.setFirstName(firstName);
            newUser.setLastName(lastName);
            newUser.setRole(role != null ? role : "ROLE_USER");
            newUser.setEnabled(true);
            newUser.setTenant(tenant);
            newUser.setCreatedAt(LocalDateTime.now());
            newUser.setUpdatedAt(LocalDateTime.now());

            userRepository.save(newUser);

            response.put("success", true);
            response.put("message", "User created successfully");
            response.put("userId", newUser.getId());

            System.out.println("✅ User created: " + email + " for tenant: " + tenant.getName());

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            e.printStackTrace();
            response.put("success", false);
            response.put("message", "Failed to create user: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    /**
     * Toggle user status (enable/disable)
     */
    @PostMapping("/{userId}/toggle-status")
    public ResponseEntity<Map<String, Object>> toggleUserStatus(@PathVariable Long userId) {
        Map<String, Object> response = new HashMap<>();

        try {
            Long tenantId = TenantContext.getTenantId();
            if (tenantId == null) {
                response.put("success", false);
                response.put("message", "No tenant context found");
                return ResponseEntity.badRequest().body(response);
            }

            Optional<User> userOpt = userRepository.findById(userId);
            if (userOpt.isEmpty()) {
                response.put("success", false);
                response.put("message", "User not found");
                return ResponseEntity.notFound().build();
            }

            User user = userOpt.get();

            // Verify user belongs to this tenant
            if (!user.getTenant().getId().equals(tenantId)) {
                response.put("success", false);
                response.put("message", "User does not belong to this tenant");
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
            }

            // Toggle status
            user.setEnabled(!user.isEnabled());
            user.setUpdatedAt(LocalDateTime.now());
            userRepository.save(user);

            response.put("success", true);
            response.put("message", "User status updated to: " + (user.isEnabled() ? "Active" : "Inactive"));

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            e.printStackTrace();
            response.put("success", false);
            response.put("message", "Failed to toggle user status: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    /**
     * Reset user password
     */
    @PostMapping("/{userId}/reset-password")
    public ResponseEntity<Map<String, Object>> resetPassword(
            @PathVariable Long userId,
            @RequestBody Map<String, String> request) {
        Map<String, Object> response = new HashMap<>();

        try {
            Long tenantId = TenantContext.getTenantId();
            if (tenantId == null) {
                response.put("success", false);
                response.put("message", "No tenant context found");
                return ResponseEntity.badRequest().body(response);
            }

            String newPassword = request.get("newPassword");
            if (newPassword == null || newPassword.length() < 6) {
                response.put("success", false);
                response.put("message", "Password must be at least 6 characters");
                return ResponseEntity.badRequest().body(response);
            }

            Optional<User> userOpt = userRepository.findById(userId);
            if (userOpt.isEmpty()) {
                response.put("success", false);
                response.put("message", "User not found");
                return ResponseEntity.notFound().build();
            }

            User user = userOpt.get();

            // Verify user belongs to this tenant
            if (!user.getTenant().getId().equals(tenantId)) {
                response.put("success", false);
                response.put("message", "User does not belong to this tenant");
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
            }

            // Update password
            user.setPassword(passwordEncoder.encode(newPassword));
            user.setUpdatedAt(LocalDateTime.now());
            userRepository.save(user);

            response.put("success", true);
            response.put("message", "Password reset successfully");

            System.out.println("✅ Password reset for user: " + user.getEmail());

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            e.printStackTrace();
            response.put("success", false);
            response.put("message", "Failed to reset password: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    /**
     * Delete user
     */
    @DeleteMapping("/{userId}")
    public ResponseEntity<Map<String, Object>> deleteUser(@PathVariable Long userId) {
        Map<String, Object> response = new HashMap<>();

        try {
            Long tenantId = TenantContext.getTenantId();
            if (tenantId == null) {
                response.put("success", false);
                response.put("message", "No tenant context found");
                return ResponseEntity.badRequest().body(response);
            }

            Optional<User> userOpt = userRepository.findById(userId);
            if (userOpt.isEmpty()) {
                response.put("success", false);
                response.put("message", "User not found");
                return ResponseEntity.notFound().build();
            }

            User user = userOpt.get();

            // Verify user belongs to this tenant
            if (!user.getTenant().getId().equals(tenantId)) {
                response.put("success", false);
                response.put("message", "User does not belong to this tenant");
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
            }

            // Prevent deleting tenant owner
            Tenant tenant = tenantRepository.findById(tenantId).orElseThrow();
            if (tenant.getOwner() != null && tenant.getOwner().getId().equals(userId)) {
                response.put("success", false);
                response.put("message", "Cannot delete tenant owner");
                return ResponseEntity.badRequest().body(response);
            }

            userRepository.delete(user);

            response.put("success", true);
            response.put("message", "User deleted successfully");

            System.out.println("✅ User deleted: " + user.getEmail());

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            e.printStackTrace();
            response.put("success", false);
            response.put("message", "Failed to delete user: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }
}