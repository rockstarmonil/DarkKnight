package com.example.darkknight.controller;

import com.example.darkknight.model.Tenant;
import com.example.darkknight.model.TenantSsoConfig;
import com.example.darkknight.model.User;
import com.example.darkknight.repository.TenantRepository;
import com.example.darkknight.repository.UserRepository;
import com.example.darkknight.service.TenantSsoConfigService;
import com.example.darkknight.util.JwtUtil;
import com.example.darkknight.util.TenantContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Controller
@RequestMapping("/jwt")
public class JwtSsoController {

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private TenantSsoConfigService ssoConfigService;

    /**
     * Step 1: Redirect user to JWT SSO login page
     * Uses dynamic tenant-based configuration
     */
    @GetMapping("/login")
    public String redirectToMiniOrange(Model model) {
        try {
            Long tenantId = TenantContext.getTenantId();
            if (tenantId == null) {
                System.err.println("❌ No tenant context found");
                return "redirect:/login?error=no_tenant";
            }

            // Get tenant's JWT configuration
            TenantSsoConfig ssoConfig = ssoConfigService.getOrCreateSsoConfig(tenantId);

            // Check if JWT is enabled
            if (!Boolean.TRUE.equals(ssoConfig.getJwtEnabled())) {
                System.err.println("❌ JWT is not enabled for this tenant");
                return "redirect:/login?error=jwt_disabled";
            }

            // Validate JWT configuration
            if (!ssoConfigService.validateJwtConfig(ssoConfig)) {
                System.err.println("❌ JWT configuration is incomplete");
                return "redirect:/login?error=jwt_not_configured";
            }

            System.out.println("🚀 Initiating JWT SSO login for tenant: " + tenantId);

            // Build the redirect link using dynamic values
            String redirectLink = ssoConfig.getMiniorangeLoginUrl()
                    + "?client_id=" + URLEncoder.encode(ssoConfig.getMiniorangeClientId(), StandardCharsets.UTF_8)
                    + "&redirect_uri=" + URLEncoder.encode(ssoConfig.getMiniorangeRedirectUri(), StandardCharsets.UTF_8);

            System.out.println("🔗 Redirecting to JWT provider: " + ssoConfig.getMiniorangeLoginUrl());

            return "redirect:" + redirectLink;

        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("❌ JWT initiation error: " + e.getMessage());
            return "redirect:/login?error=" + URLEncoder.encode(e.getMessage(), StandardCharsets.UTF_8);
        }
    }

    /**
     * Step 2: Handle JWT Callback and Authentication
     */
    @GetMapping({"/callback", "/callback/{token}"})
    public String handleJwtCallback(
            @PathVariable(name = "token", required = false) String pathToken,
            @RequestParam(name = "token", required = false) String queryToken,
            HttpServletRequest request,
            Model model,
            HttpSession session) {

        try {
            Long tenantId = TenantContext.getTenantId();
            if (tenantId == null) {
                System.err.println("❌ No tenant context in JWT callback");
                model.addAttribute("error", "Invalid tenant context");
                return "login";
            }

            System.out.println("📥 JWT callback received for tenant: " + tenantId);

            // Get tenant's JWT configuration
            TenantSsoConfig ssoConfig = ssoConfigService.getOrCreateSsoConfig(tenantId);

            if (!Boolean.TRUE.equals(ssoConfig.getJwtEnabled())) {
                model.addAttribute("error", "JWT SSO is not enabled for this tenant");
                return "login";
            }

            String token = (queryToken != null) ? queryToken : pathToken;
            String clientSecret = ssoConfig.getMiniorangeClientSecret();

            System.out.println("🔑 Using tenant-specific JWT secret");

            if (token == null || token.isBlank()) {
                System.err.println("❌ No JWT token received");
                model.addAttribute("error", "No token received from JWT provider");
                return "login";
            }

            // Get tenant
            Tenant tenant = tenantRepository.findById(tenantId)
                    .orElseThrow(() -> new RuntimeException("Tenant not found"));

            // Validate JWT using tenant-specific secret
            Map<String, Object> claims = jwtUtil.validateToken(token, clientSecret);
            System.out.println("✅ JWT Claims: " + claims);

            String email = (String) claims.getOrDefault("email", claims.get("sub"));
            String name = (String) claims.getOrDefault("name", claims.getOrDefault("fullName", "JWT User"));
            String firstName = (String) claims.getOrDefault("given_name", claims.getOrDefault("firstName", name));
            String lastName = (String) claims.getOrDefault("family_name", claims.getOrDefault("lastName", ""));

            if (email == null || email.isBlank()) {
                System.err.println("❌ No email in JWT claims");
                model.addAttribute("error", "Token invalid — missing email claim");
                return "login";
            }

            System.out.println("👤 JWT user email: " + email);

            // Find or create user for this tenant
            User user = userRepository.findByEmailAndTenantId(email, tenantId)
                    .orElseGet(() -> {
                        System.out.println("➕ Creating new JWT user: " + email);
                        User newUser = new User();
                        newUser.setEmail(email);
                        newUser.setUsername(email);
                        newUser.setFirstName(firstName);
                        newUser.setLastName(lastName);
                        newUser.setRole("ROLE_USER");
                        newUser.setEnabled(true);
                        newUser.setTenant(tenant);
                        newUser.setCreatedAt(LocalDateTime.now());
                        newUser.setUpdatedAt(LocalDateTime.now());
                        return newUser;
                    });

            user.setUpdatedAt(LocalDateTime.now());
            userRepository.save(user);
            System.out.println("💾 JWT user saved: " + user.getEmail());

            // Setup Spring Security
            List<SimpleGrantedAuthority> authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority(user.getRole()));

            var auth = new UsernamePasswordAuthenticationToken(
                    user.getEmail(), null, authorities);
            SecurityContextHolder.getContext().setAuthentication(auth);

            // Persist context & user in session
            session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());
            session.setAttribute("user", user);
            session.setAttribute("isLoggedIn", true);
            session.setAttribute("jwtAuthenticated", true);

            System.out.println("✅ JWT user authenticated successfully: " + user.getEmail());

            // Redirect based on role
            String redirectUrl = "/dashboard";
            if ("ROLE_ADMIN".equals(user.getRole())) {
                redirectUrl = "/tenant-admin/dashboard";
            }

            return "redirect:" + redirectUrl;

        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("❌ JWT callback error: " + e.getMessage());
            model.addAttribute("error", "SSO failed: " + e.getMessage());
            return "login";
        }
    }

    /**
     * Logout
     */
    @GetMapping("/logout")
    public String logout(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            User user = (User) session.getAttribute("user");
            if (user != null) {
                System.out.println("👋 Logging out JWT user: " + user.getEmail());
            }
            session.invalidate();
        }
        SecurityContextHolder.clearContext();
        System.out.println("✅ JWT logout successful");
        return "redirect:/login?logout";
    }
}