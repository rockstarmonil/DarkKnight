package com.example.darkknight.controller;

import com.example.darkknight.model.Tenant;
import com.example.darkknight.model.TenantSsoConfig;
import com.example.darkknight.model.User;
import com.example.darkknight.repository.TenantRepository;
import com.example.darkknight.repository.UserRepository;
import com.example.darkknight.security.CustomUserDetails;
import com.example.darkknight.service.TenantSsoConfigService;
import com.example.darkknight.util.TenantContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Controller
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

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

    // ========================================
    // LOGIN PAGE (GET)
    // ========================================

    @GetMapping("/login")
    public String loginPage(Model model, HttpServletRequest request) {
        Long tenantId = TenantContext.getTenantId();
        String subdomain = TenantContext.getSubdomain();

        System.out.println("🔐 Login page requested - Tenant ID: " + tenantId + ", Subdomain: " + subdomain);

        addLoginPageAttributes(model, tenantId, subdomain, request);

        return "login";
    }

    // ========================================
    // LOGIN FORM SUBMISSION (POST)
    // ========================================

    @PostMapping("/login")
    public String loginUser(@RequestParam String email,
            @RequestParam String password,
            HttpServletRequest request,
            Model model) {

        Long tenantId = TenantContext.getTenantId();
        String subdomain = TenantContext.getSubdomain();

        System.out.println("🔐 Login attempt - Email: " + email + ", Subdomain: " + subdomain);
        System.out.println("📍 TenantContext - TenantId: " + tenantId + ", Subdomain: " + subdomain);

        // ==========================================
        // 1. SUPER ADMIN LOGIN CHECK
        // ==========================================
        if ("admin@system.com".equalsIgnoreCase(email) && "admin".equals(password)) {
            // Super admin cannot access tenant subdomains
            if (subdomain != null && !subdomain.isEmpty()) {
                model.addAttribute("error", "Super admin cannot access tenant subdomains. Please use: " +
                        protocol + "://" + appDomain + (isStandardPort() ? "" : ":" + port) + "/login");
                addLoginPageAttributes(model, tenantId, subdomain, request);
                return "login";
            }

            // Create super admin session
            HttpSession session = request.getSession(true);
            session.setAttribute("superAdmin", "admin@system.com");
            session.setAttribute("isLoggedIn", true);

            var authority = new SimpleGrantedAuthority("ROLE_SUPER_ADMIN");
            var auth = new UsernamePasswordAuthenticationToken(
                    "admin@system.com", null, Collections.singletonList(authority));
            SecurityContextHolder.getContext().setAuthentication(auth);
            session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());

            System.out.println("✅ Super Admin logged in successfully");
            return "redirect:/main-admin/dashboard";
        }

        // ==========================================
        // 2. NORMAL USER VALIDATION
        // ==========================================
        // When logging in through a tenant subdomain, scope the lookup to that tenant.
        // This ensures that if two tenants share the same email address each user only
        // ever authenticates against their own tenant's record.
        User user;
        if (tenantId != null) {
            user = userRepository.findByEmailAndTenantId(email, tenantId).orElse(null);
        } else {
            user = userRepository.findByEmail(email).orElse(null);
        }

        if (user == null || !passwordEncoder.matches(password, user.getPassword())) {
            System.out.println("❌ Invalid credentials for email: " + email);
            model.addAttribute("error", "Invalid email or password!");
            addLoginPageAttributes(model, tenantId, subdomain, request);
            return "login";
        }

        System.out.println("✅ User found: " + user.getEmail() + " (Role: " + user.getRole() + ")");
        System.out.println("📍 User Tenant: " + (user.getTenant() != null ? user.getTenant().getName() : "NO TENANT"));
        System.out.println("📍 User Tenant Subdomain: "
                + (user.getTenant() != null ? user.getTenant().getSubdomain() : "NO SUBDOMAIN"));
        System.out.println("📍 User Enabled: " + user.isEnabled());

        // ==========================================
        // 3. TENANT VALIDATION
        // ==========================================
        if (user.getTenant() != null) {
            Tenant userTenant = user.getTenant();
            String userTenantSubdomain = userTenant.getSubdomain();

            System.out.println("🔍 Comparing subdomains - User's tenant: '" + userTenantSubdomain + "', Current: '"
                    + subdomain + "'");

            // Check if user is accessing correct tenant subdomain
            if (subdomain == null || !userTenantSubdomain.equalsIgnoreCase(subdomain)) {
                String correctUrl = protocol + "://" + userTenantSubdomain + "." + appDomain +
                        (isStandardPort() ? "" : ":" + port) + "/login";

                String errorMsg = subdomain == null
                        ? "Please login at: " + correctUrl
                        : "You cannot login to this tenant. Please use: " + correctUrl;

                System.out.println("❌ Tenant mismatch - User tenant: " + userTenantSubdomain + ", Current subdomain: "
                        + subdomain);
                model.addAttribute("error", errorMsg);
                addLoginPageAttributes(model, tenantId, subdomain, request);
                return "login";
            }

            // Check if tenant is active
            if (!userTenant.isActive()) {
                System.out.println("❌ Tenant is suspended: " + userTenant.getName());
                model.addAttribute("error", "This tenant is currently suspended. Please contact support.");
                addLoginPageAttributes(model, tenantId, subdomain, request);
                return "login";
            }

            System.out.println("✅ Tenant validation passed - Tenant: " + userTenant.getName() + " is active");
        } else {
            // User without tenant trying to access tenant subdomain
            if (subdomain != null) {
                System.out.println("❌ User has no tenant but accessing subdomain: " + subdomain);
                model.addAttribute("error", "This user does not belong to any tenant.");
                addLoginPageAttributes(model, tenantId, subdomain, request);
                return "login";
            }
        }

        // ==========================================
        // 4. CHECK IF USER IS ENABLED
        // ==========================================
        if (!user.isEnabled()) {
            System.out.println("❌ User account is disabled: " + user.getEmail());
            model.addAttribute("error", "Your account has been disabled. Please contact your administrator.");
            addLoginPageAttributes(model, tenantId, subdomain, request);
            return "login";
        }

        // ==========================================
        // 5. CREATE AUTHENTICATION
        // ==========================================
        CustomUserDetails userDetails = new CustomUserDetails(user);

        var auth = new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(auth);

        // ==========================================
        // 6. CREATE SESSION
        // ==========================================
        HttpSession session = request.getSession(true);
        session.setAttribute("user", user);
        session.setAttribute("isLoggedIn", true);
        session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());

        System.out.println("✅ User authenticated successfully: " + user.getEmail());
        System.out.println("✅ Authentication created with authorities: " + userDetails.getAuthorities());

        // ==========================================
        // 7. ROLE-BASED REDIRECT
        // ==========================================
        if ("ROLE_ADMIN".equalsIgnoreCase(user.getRole())) {
            System.out.println("🎯 Redirecting ROLE_ADMIN to tenant admin dashboard");
            return "redirect:/tenant-admin/dashboard";
        } else {
            System.out.println("🎯 Redirecting ROLE_USER to user dashboard");
            return "redirect:/user/dashboard";
        }
    }

    // ========================================
    // DASHBOARD REDIRECT LOGIC
    // ========================================

    @GetMapping("/dashboard")
    public String redirectDashboard(Model model, Authentication authentication) {

        System.out.println(
                "🔄 Dashboard redirect - Principal type: " + authentication.getPrincipal().getClass().getName());

        // Super Admin redirect
        if (authentication.getPrincipal() instanceof String &&
                "admin@system.com".equalsIgnoreCase(authentication.getName())) {
            System.out.println("🎯 Redirecting super admin to main-admin dashboard");
            return "redirect:/main-admin/dashboard";
        }

        // Normal user redirect
        if (authentication.getPrincipal() instanceof CustomUserDetails) {
            String principalEmail = ((CustomUserDetails) authentication.getPrincipal()).getUsername();

            User user = userRepository.findByEmail(principalEmail)
                    .orElseThrow(() -> new RuntimeException("User not found: " + principalEmail));

            System.out.println("🔄 User role: " + user.getRole());

            if ("ROLE_ADMIN".equalsIgnoreCase(user.getRole())) {
                System.out.println("🎯 Redirecting to tenant-admin dashboard");
                return "redirect:/tenant-admin/dashboard";
            } else {
                System.out.println("🎯 Redirecting to user dashboard");
                return "redirect:/user/dashboard";
            }
        }

        throw new RuntimeException("Invalid authentication principal type: " +
                authentication.getPrincipal().getClass().getName());
    }

    // ========================================
    // MAIN ADMIN DASHBOARD (SUPER ADMIN)
    // ========================================

    @GetMapping("/main-admin/dashboard")
    public String mainAdminDashboard(HttpSession session, Model model) {
        String superAdmin = SecurityContextHolder.getContext().getAuthentication().getName();

        System.out.println("🔍 Main Admin Dashboard - Authentication name: " + superAdmin);

        if (superAdmin == null || !superAdmin.equalsIgnoreCase("admin@system.com")) {
            System.out.println("❌ Unauthorized access to main admin dashboard");
            return "redirect:/login";
        }

        // Create super admin user object for display
        User adminUser = new User();
        adminUser.setUsername("admin@system.com");
        adminUser.setEmail("admin@system.com");
        adminUser.setFirstName("Super");
        adminUser.setLastName("Admin");
        adminUser.setRole("ROLE_SUPER_ADMIN");
        adminUser.setEnabled(true);
        adminUser.setCreatedAt(LocalDateTime.now());
        adminUser.setUpdatedAt(LocalDateTime.now());

        // Get all users
        List<User> allUsers = userRepository.findAll();
        List<User> admins = allUsers.stream()
                .filter(u -> u.getRole() != null && u.getRole().equalsIgnoreCase("ROLE_ADMIN"))
                .collect(Collectors.toList());
        List<User> users = allUsers.stream()
                .filter(u -> u.getRole() != null && u.getRole().equalsIgnoreCase("ROLE_USER"))
                .collect(Collectors.toList());

        // Get all tenants
        List<Tenant> allTenants = tenantRepository.findAll();
        long totalTenants = allTenants.size();
        long activeTenants = allTenants.stream().filter(Tenant::isActive).count();

        model.addAttribute("user", adminUser);
        model.addAttribute("superAdmin", superAdmin);
        model.addAttribute("admins", admins);
        model.addAttribute("users", users);
        model.addAttribute("totalAdmins", (long) admins.size());
        model.addAttribute("totalUsers", (long) users.size());
        model.addAttribute("tenants", allTenants);
        model.addAttribute("totalTenants", totalTenants);
        model.addAttribute("activeTenants", activeTenants);

        System.out.println("✅ Main Admin Dashboard - Tenants: " + totalTenants +
                ", Admins: " + admins.size() + ", Users: " + users.size());

        return "main-admin-dashboard";
    }

    // ========================================
    // USER DASHBOARD
    // ========================================

    @GetMapping("/user/dashboard")
    public String userDashboard(Model model, Authentication authentication, HttpServletRequest request) {

        System.out.println("========================================");
        System.out.println("📊 USER DASHBOARD ACCESS ATTEMPT");
        System.out.println("========================================");
        System.out.println("🔐 Authentication: " + (authentication != null ? "Present" : "NULL"));

        if (authentication != null) {
            System.out.println("👤 Principal Type: " + authentication.getPrincipal().getClass().getName());
            System.out.println("👤 Principal: " + authentication.getName());
            System.out.println("🔑 Authorities: " + authentication.getAuthorities());
            System.out.println("🔓 Authenticated: " + authentication.isAuthenticated());
        }

        // Check tenant context
        Long tenantId = TenantContext.getTenantId();
        String subdomain = TenantContext.getSubdomain();
        System.out.println("🏢 TenantContext - ID: " + tenantId + ", Subdomain: " + subdomain);

        // Try to restore from session if null
        if (tenantId == null) {
            HttpSession session = request.getSession(false);
            if (session != null) {
                tenantId = (Long) session.getAttribute("oauth_tenant_id");
                subdomain = (String) session.getAttribute("oauth_subdomain");

                if (tenantId != null) {
                    TenantContext.setTenantId(tenantId);
                    TenantContext.setSubdomain(subdomain);
                    System.out.println("✅ Restored tenant context from session: " + tenantId);
                }
            }
        }

        if (authentication == null || !(authentication.getPrincipal() instanceof CustomUserDetails)) {
            System.err.println("❌ Invalid authentication or principal type");
            System.err.println("❌ Expected CustomUserDetails but got: " +
                    (authentication != null ? authentication.getPrincipal().getClass().getName() : "null"));
            return "redirect:/login?error=invalid_auth";
        }

        CustomUserDetails customUser = (CustomUserDetails) authentication.getPrincipal();
        String principalEmail = customUser.getUsername();

        System.out.println("👤 Loading user from database: " + principalEmail);

        User user = userRepository.findByEmail(principalEmail)
                .orElseThrow(() -> new RuntimeException("User not found: " + principalEmail));

        System.out.println("✅ User loaded: " + user.getEmail() + " (Role: " + user.getRole() + ")");

        model.addAttribute("user", user);

        System.out.println("========================================");
        System.out.println("✅ USER DASHBOARD LOADED SUCCESSFULLY");
        System.out.println("========================================");

        return "user-dashboard";
    }

    // ========================================
    // REGISTRATION
    // ========================================

    @GetMapping("/register")
    public String registerPage() {
        return "register";
    }

    @PostMapping("/api/auth/register")
    @ResponseBody
    public Map<String, Object> registerUser(@RequestBody User user) {
        Map<String, Object> response = new HashMap<>();

        try {
            // Check if email already exists
            if (userRepository.findByEmail(user.getEmail()).isPresent()) {
                response.put("success", false);
                response.put("message", "Email already exists!");
                return response;
            }

            // Set username equal to email
            user.setUsername(user.getEmail());
            user.setPassword(passwordEncoder.encode(user.getPassword()));
            user.setRole("ROLE_USER");
            user.setEnabled(true);
            user.setCreatedAt(LocalDateTime.now());
            user.setUpdatedAt(LocalDateTime.now());

            userRepository.save(user);

            response.put("success", true);
            response.put("message", "User registered successfully!");

            System.out.println("✅ New user registered: " + user.getEmail());

        } catch (Exception e) {
            e.printStackTrace();
            response.put("success", false);
            response.put("message", "Registration failed: " + e.getMessage());
        }

        return response;
    }

    // ========================================
    // UTILITY METHODS
    // ========================================

    /**
     * Add required attributes for login page
     */
    private void addLoginPageAttributes(Model model, Long tenantId, String subdomain, HttpServletRequest request) {
        String tenantName = "Application";
        boolean samlEnabled = false;
        boolean oauthEnabled = false;
        boolean jwtEnabled = false;
        boolean adEnabled = false;
        TenantSsoConfig ssoConfig = null;
        String currentDomain = getCurrentDomain();

        if (tenantId != null) {
            Optional<Tenant> tenantOpt = tenantRepository.findById(tenantId);
            if (tenantOpt.isPresent()) {
                Tenant tenant = tenantOpt.get();
                tenantName = tenant.getName();

                Optional<TenantSsoConfig> configOpt = ssoConfigService.getSsoConfigByTenantId(tenantId);
                if (configOpt.isPresent()) {
                    ssoConfig = configOpt.get();
                    samlEnabled = Boolean.TRUE.equals(ssoConfig.getSamlEnabled());
                    oauthEnabled = Boolean.TRUE.equals(ssoConfig.getOauthEnabled());
                    jwtEnabled = Boolean.TRUE.equals(ssoConfig.getJwtEnabled());
                    adEnabled = Boolean.TRUE.equals(ssoConfig.getAdEnabled());
                }
            }
        }

        model.addAttribute("tenantName", tenantName);
        model.addAttribute("subdomain", subdomain);
        model.addAttribute("currentDomain", currentDomain);
        model.addAttribute("samlEnabled", samlEnabled);
        model.addAttribute("oauthEnabled", oauthEnabled);
        model.addAttribute("jwtEnabled", jwtEnabled);
        model.addAttribute("adEnabled", adEnabled);
        model.addAttribute("anySsoEnabled", samlEnabled || oauthEnabled || jwtEnabled || adEnabled);

        if (ssoConfig != null) {
            model.addAttribute("ssoConfig", ssoConfig);
        }
    }

    /**
     * Get current domain for display
     */
    private String getCurrentDomain() {
        if ("development".equalsIgnoreCase(environment) || "localhost".equals(appDomain)) {
            return "localhost:" + port;
        }

        return appDomain + (isStandardPort() ? "" : ":" + port);
    }

    /**
     * Check if using standard HTTP/HTTPS port
     */
    private boolean isStandardPort() {
        return ("http".equals(protocol) && "80".equals(port)) ||
                ("https".equals(protocol) && "443".equals(port));
    }
}