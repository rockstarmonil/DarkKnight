package com.example.darkknight.controller;

import com.example.darkknight.model.Tenant;
import com.example.darkknight.model.User;
import com.example.darkknight.repository.TenantRepository;
import com.example.darkknight.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Controller
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    // ✅ Serve login page
    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    // ✅ Handle login manually - This catches admin/admin BEFORE Spring Security
    @PostMapping("/login")
    public String loginUser(@RequestParam String username,
                            @RequestParam String password,
                            HttpServletRequest request,
                            Model model) {

        // Get current subdomain from request
        String host = request.getServerName();
        String subdomain = extractSubdomain(host);

        // 🟣 1️⃣ Super Admin hardcoded login check (FIRST PRIORITY)
        // Super admin can ONLY login on main domain (no subdomain)
        if ("admin".equalsIgnoreCase(username) && "admin".equals(password)) {
            if (subdomain != null && !subdomain.isEmpty()) {
                model.addAttribute("error", "Super admin cannot access tenant subdomains. Please use: http://localhost:8080/login");
                return "login";
            }

            HttpSession session = request.getSession(true);
            session.setAttribute("superAdmin", username);
            session.setAttribute("isLoggedIn", true);

            var authority = new SimpleGrantedAuthority("ROLE_SUPER_ADMIN");
            var auth = new UsernamePasswordAuthenticationToken(
                    "admin", null, Collections.singletonList(authority));
            SecurityContextHolder.getContext().setAuthentication(auth);
            session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());

            System.out.println("✅ Super Admin logged in successfully");
            return "redirect:/main-admin/dashboard";
        }

        // 🟣 2️⃣ Normal user validation from DB
        User user = userRepository.findByUsername(username).orElse(null);

        if (user == null || !passwordEncoder.matches(password, user.getPassword())) {
            model.addAttribute("error", "Invalid username or password!");
            return "login";
        }

        // 🟣 3️⃣ TENANT VALIDATION - Check if user's tenant matches current subdomain
        if (user.getTenant() != null) {
            String userTenantSubdomain = user.getTenant().getSubdomain();

            // User must login on their tenant's subdomain
            if (subdomain == null) {
                model.addAttribute("error", "Please login at: http://" + userTenantSubdomain + ".localhost:8080/login");
                return "login";
            }

            if (!userTenantSubdomain.equals(subdomain)) {
                model.addAttribute("error", "You cannot login to this tenant. Please use: http://" + userTenantSubdomain + ".localhost:8080/login");
                return "login";
            }

            // Check if tenant is active
            if (!user.getTenant().isActive()) {
                model.addAttribute("error", "This tenant is currently suspended. Please contact support.");
                return "login";
            }
        } else {
            // Users without tenant can only login on main domain
            if (subdomain != null) {
                model.addAttribute("error", "This user does not belong to any tenant.");
                return "login";
            }
        }

        HttpSession session = request.getSession(true);
        session.setAttribute("user", user);
        session.setAttribute("isLoggedIn", true);

        var authority = new SimpleGrantedAuthority(user.getRole());
        var auth = new UsernamePasswordAuthenticationToken(
                user.getUsername(), null, Collections.singletonList(authority));
        SecurityContextHolder.getContext().setAuthentication(auth);
        session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());

        // 🟣 4️⃣ Role-based redirect
        if (user.getRole().equalsIgnoreCase("ROLE_ADMIN")) {
            return "redirect:/admin/dashboard";
        } else {
            return "redirect:/user/dashboard";
        }
    }

    /**
     * Extract subdomain from host
     */
    private String extractSubdomain(String host) {
        if (host == null) return null;

        // Remove port if present
        if (host.contains(":")) {
            host = host.substring(0, host.indexOf(":"));
        }

        // Split by dots
        String[] parts = host.split("\\.");

        // For localhost: "acme.localhost" -> parts = ["acme", "localhost"]
        if (parts.length >= 2 && "localhost".equals(parts[parts.length - 1])) {
            return parts[0];
        }

        // For production: "acme.yourdomain.com" -> parts = ["acme", "yourdomain", "com"]
        if (parts.length >= 3) {
            return parts[0];
        }

        // No subdomain found
        return null;
    }

    // ✅ Serve register page
    @GetMapping("/register")
    public String registerPage() {
        return "register";
    }

    // ✅ Redirect user after login (used by Spring Security session)
    @GetMapping("/dashboard")
    public String redirectDashboard(Model model, Authentication authentication) {
        String username = authentication.getName();

        if ("admin".equalsIgnoreCase(username)) {
            return "redirect:/main-admin/dashboard";
        }

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (user.getRole().equalsIgnoreCase("ROLE_ADMIN")) {
            return "redirect:/admin/dashboard";
        } else {
            return "redirect:/user/dashboard";
        }
    }

    // ✅ Super Admin Dashboard (Updated with Tenants)
    @GetMapping("/main-admin/dashboard")
    public String mainAdminDashboard(HttpSession session, Model model) {
        String superAdmin = (String) session.getAttribute("superAdmin");
        if (superAdmin == null) {
            return "redirect:/login";
        }

        User adminUser = new User();
        adminUser.setUsername("admin");
        adminUser.setEmail("admin@system.com");
        adminUser.setFirstName("Super");
        adminUser.setLastName("Admin");
        adminUser.setRole("ROLE_SUPER_ADMIN");
        adminUser.setEnabled(true);
        adminUser.setCreatedAt(LocalDateTime.now());
        adminUser.setUpdatedAt(LocalDateTime.now());

        List<User> allUsers = userRepository.findAll();

        List<User> admins = allUsers.stream()
                .filter(u -> u.getRole() != null && u.getRole().equalsIgnoreCase("ROLE_ADMIN"))
                .collect(Collectors.toList());

        List<User> users = allUsers.stream()
                .filter(u -> u.getRole() != null && u.getRole().equalsIgnoreCase("ROLE_USER"))
                .collect(Collectors.toList());

        // ✅ NEW: Get all tenants
        List<Tenant> allTenants = tenantRepository.findAll();
        long totalTenants = allTenants.size();
        long activeTenants = allTenants.stream().filter(Tenant::isActive).count();

        long totalAdmins = admins.size();
        long totalUsers = users.size();

        model.addAttribute("user", adminUser);
        model.addAttribute("superAdmin", superAdmin);
        model.addAttribute("admins", admins);
        model.addAttribute("users", users);
        model.addAttribute("totalAdmins", totalAdmins);
        model.addAttribute("totalUsers", totalUsers);
        model.addAttribute("tenants", allTenants);
        model.addAttribute("totalTenants", totalTenants);
        model.addAttribute("activeTenants", activeTenants);

        System.out.println("✅ Main Admin Dashboard - Tenants: " + totalTenants + ", Admins: " + totalAdmins + ", Users: " + totalUsers);

        return "main-admin-dashboard";
    }

    // ✅ Admin Dashboard (Tenant-specific)
    @GetMapping("/admin/dashboard")
    public String adminDashboard(Model model, Authentication authentication) {
        String username = authentication.getName();
        User admin = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Admin not found"));

        // Check if this is a tenant admin
        if (admin.getTenant() != null) {
            // TENANT ADMIN - Show only their tenant's users
            Tenant tenant = admin.getTenant();

            // Get only users from this tenant (optimized query)
            List<User> tenantUsers = userRepository.findByTenantId(tenant.getId());

            // Calculate stats
            long totalUsers = tenantUsers.size();
            long activeUsers = tenantUsers.stream().filter(User::isEnabled).count();
            long totalAdmins = tenantUsers.stream()
                    .filter(u -> "ROLE_ADMIN".equals(u.getRole()))
                    .count();
            int availableSlots = tenant.getMaxUsers() - (int) totalUsers;

            model.addAttribute("admin", admin);
            model.addAttribute("tenant", tenant);
            model.addAttribute("users", tenantUsers);
            model.addAttribute("totalUsers", totalUsers);
            model.addAttribute("activeUsers", activeUsers);
            model.addAttribute("totalAdmins", totalAdmins);
            model.addAttribute("availableSlots", availableSlots);

            System.out.println("✅ Tenant Admin Dashboard - Tenant: " + tenant.getName() + ", Users: " + totalUsers);

            return "tenant-admin-dashboard";
        } else {
            // Regular admin without tenant (shouldn't happen normally)
            model.addAttribute("admin", admin);
            model.addAttribute("users", userRepository.findAll());
            return "admin-dashboard";
        }
    }

    // ✅ User Dashboard
    @GetMapping("/user/dashboard")
    public String userDashboard(Model model, Authentication authentication) {
        String username = authentication.getName();
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        model.addAttribute("user", user);
        return "user-dashboard";
    }

    // ✅ Register User API (AJAX)
    @PostMapping("/api/auth/register")
    @ResponseBody
    public Map<String, Object> registerUser(@RequestBody User user) {
        Map<String, Object> response = new HashMap<>();

        if (userRepository.findByUsername(user.getUsername()).isPresent()) {
            response.put("message", "Username already exists!");
            return response;
        }

        if (userRepository.findByEmail(user.getEmail()).isPresent()) {
            response.put("message", "Email already exists!");
            return response;
        }

        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRole("ROLE_USER");
        user.setEnabled(true);
        user.setCreatedAt(LocalDateTime.now());
        user.setUpdatedAt(LocalDateTime.now());

        userRepository.save(user);
        response.put("message", "User registered successfully!");
        return response;
    }
}