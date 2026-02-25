package com.example.darkknight.controller;

import com.example.darkknight.model.Tenant;
import com.example.darkknight.model.TenantSsoConfig;
import com.example.darkknight.model.User;
import com.example.darkknight.repository.TenantRepository;
import com.example.darkknight.repository.UserRepository;
import com.example.darkknight.security.CustomUserDetails;
import com.example.darkknight.service.TenantSsoConfigService;
import com.example.darkknight.util.JwtUtil;
import com.example.darkknight.util.TenantContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
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
     */
    @GetMapping("/login")
    public String redirectToMiniOrange(HttpServletRequest request) {
        try {
            Long tenantId = TenantContext.getTenantId();
            String subdomain = TenantContext.getSubdomain();

            System.out.println("========================================");
            System.out.println("🚀 JWT Login Initiated");
            System.out.println("========================================");
            System.out.println("📍 Tenant ID: " + tenantId);
            System.out.println("📍 Subdomain: " + subdomain);

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

            // Store tenant context in session for callback
            HttpSession session = request.getSession(true);
            session.setAttribute("jwt_tenant_id", tenantId);
            session.setAttribute("jwt_subdomain", subdomain);

            System.out.println("💾 Stored in session:");
            System.out.println("   - Tenant ID: " + tenantId);
            System.out.println("   - Subdomain: " + subdomain);

            // Build the redirect link using dynamic values
            String redirectLink = ssoConfig.getMiniorangeLoginUrl()
                    + "?client_id=" + URLEncoder.encode(ssoConfig.getMiniorangeClientId(), StandardCharsets.UTF_8)
                    + "&redirect_uri=" + URLEncoder.encode(ssoConfig.getMiniorangeRedirectUri(), StandardCharsets.UTF_8)
                    + "&state=" + tenantId;

            System.out.println("🔗 JWT Login URL: " + ssoConfig.getMiniorangeLoginUrl());
            System.out.println("🔗 Client ID: " + ssoConfig.getMiniorangeClientId());
            System.out.println("🔗 Redirect URI: " + ssoConfig.getMiniorangeRedirectUri());
            System.out.println("🔗 Full URL: " + redirectLink);
            System.out.println("========================================");

            return "redirect:" + redirectLink;

        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("❌ JWT initiation error: " + e.getMessage());
            return "redirect:/login?error=" + URLEncoder.encode(e.getMessage(), StandardCharsets.UTF_8);
        }
    }

    /**
     * Step 2: Handle JWT Callback and Authentication
     *
     * <p>
     * Supports three token delivery modes used by different IdPs:
     * <ol>
     * <li><b>Query param</b> — {@code /jwt/callback?token=TOKEN} (most IdPs)</li>
     * <li><b>Path segment</b> — {@code /jwt/callback/TOKEN} (slash-separated)</li>
     * <li><b>Direct append</b>— {@code /jwt/callbackTOKEN} (MiniOrange
     * behaviour)</li>
     * <li><b>id_token param</b>— {@code /jwt/callback?id_token=TOKEN} (OIDC)</li>
     * </ol>
     */
    @GetMapping(value = { "/callback", "/callback/**", "/callback*" })
    public String handleJwtCallback(
            @RequestParam(name = "token", required = false) String queryToken,
            @RequestParam(name = "id_token", required = false) String idToken,
            @RequestParam(name = "error", required = false) String error,
            @RequestParam(name = "state", required = false) String state,
            HttpServletRequest request,
            Model model) {

        System.out.println("========================================");
        System.out.println("🔔 JWT Callback Received");
        System.out.println("========================================");
        System.out.println("📝 Query Token: " + (queryToken != null ? "present" : "null"));
        System.out.println("📝 ID Token (OIDC): " + (idToken != null ? "present" : "null"));
        System.out.println("📝 URI-path token: (will extract from URI below)");
        System.out.println("📝 Error: " + error);
        System.out.println("📝 State: " + state);
        System.out.println("📝 Request URI: " + request.getRequestURI());

        // =====================================================================
        // ⭐ Extract token from raw URI for MiniOrange's direct-append behaviour.
        // MiniOrange sends: https://tenant.domain.com/jwt/callback<TOKEN>
        // (no slash or query-param separator between "/callback" and the token).
        // Spring MVC can route it via "/callback*" but cannot bind a @PathVariable
        // from the directly-concatenated segment, so we extract it manually here.
        // =====================================================================
        String uriToken = null;
        String requestUri = request.getRequestURI();
        final String CALLBACK_PREFIX = "/jwt/callback";
        if (requestUri.startsWith(CALLBACK_PREFIX)) {
            String suffix = requestUri.substring(CALLBACK_PREFIX.length());
            if (!suffix.isEmpty()) {
                // Strip leading "/" for the /jwt/callback/TOKEN (slash-separated) case
                if (suffix.startsWith("/")) {
                    suffix = suffix.substring(1);
                }
                if (!suffix.isEmpty()) {
                    uriToken = suffix;
                    System.out.println("🔗 Token extracted from URI path, length: " + uriToken.length());
                }
            }
        }

        if (error != null) {
            System.err.println("❌ JWT provider returned error: " + error);
            return "redirect:/login?error=" + URLEncoder.encode("JWT Error: " + error, StandardCharsets.UTF_8);
        }

        try {
            // Resolve tenant context
            Long tenantId = resolveTenantId(request, state);

            if (tenantId == null) {
                System.err.println("❌ Could not determine tenant context");
                return "redirect:/login?error=no_tenant_context";
            }

            System.out.println("✅ Tenant Context Resolved - ID: " + tenantId);

            // Get tenant's JWT configuration
            TenantSsoConfig ssoConfig = ssoConfigService.getOrCreateSsoConfig(tenantId);

            if (!Boolean.TRUE.equals(ssoConfig.getJwtEnabled())) {
                System.err.println("❌ JWT is not enabled for tenant: " + tenantId);
                return "redirect:/login?error=jwt_not_enabled";
            }

            // Get tenant
            Tenant tenant = tenantRepository.findById(tenantId)
                    .orElseThrow(() -> new RuntimeException("Tenant not found: " + tenantId));

            System.out.println("🏢 Tenant: " + tenant.getName() + " (ID: " + tenant.getId() + ")");

            // Token priority: queryToken > idToken (OIDC) > uriToken (from path or
            // MiniOrange direct-append)
            String token = queryToken != null ? queryToken
                    : (idToken != null ? idToken
                            : uriToken);
            System.out.println("📝 Token source: " + (queryToken != null ? "query param (?token=)"
                    : idToken != null ? "id_token param (OIDC)"
                            : uriToken != null ? "URI path (slash or MiniOrange direct-append)" : "NONE"));
            String clientSecret = ssoConfig.getMiniorangeClientSecret();

            if (token == null || token.isBlank()) {
                System.err.println("❌ No JWT token received");
                return "redirect:/login?error=no_jwt_token";
            }

            System.out.println("✅ JWT token received (length: " + token.length() + ")");
            System.out.println("🔑 Using tenant-specific JWT secret");
            System.out.println("🔐 Algorithm: "
                    + (ssoConfig.getJwtAlgorithm() != null ? ssoConfig.getJwtAlgorithm() : "HS256 (default)"));

            // ==========================================
            // Validate JWT token
            // ==========================================
            System.out.println("🔄 Validating JWT token");

            // Use the tenant's configured algorithm; fall back to HS256 for safety
            String algorithm = ssoConfig.getJwtAlgorithm() != null && !ssoConfig.getJwtAlgorithm().isBlank()
                    ? ssoConfig.getJwtAlgorithm()
                    : "HS256";

            Map<String, Object> claims = jwtUtil.validateToken(token, clientSecret, algorithm);
            System.out.println("✅ JWT token validated successfully");
            System.out.println("📄 JWT Claims: " + claims);

            // Extract user information
            String email = (String) claims.getOrDefault("email", claims.get("sub"));
            String name = (String) claims.getOrDefault("name", claims.getOrDefault("fullName", "JWT User"));
            String firstName = (String) claims.getOrDefault("given_name",
                    claims.getOrDefault("firstName", name.split(" ")[0]));
            String lastName = (String) claims.getOrDefault("family_name",
                    claims.getOrDefault("lastName", name.split(" ").length > 1 ? name.split(" ")[1] : ""));

            if (email == null || email.isBlank()) {
                System.err.println("❌ No email in JWT claims");
                return "redirect:/login?error=no_email";
            }

            System.out.println("👤 JWT User - Email: " + email + ", Name: " + firstName + " " + lastName);

            // ==========================================
            // Find or create user
            // ==========================================
            System.out.println("🔄 Finding or creating user");

            final Long finalTenantId = tenantId;
            User user = userRepository.findByEmailAndTenantId(email, tenantId)
                    .orElseGet(() -> {
                        System.out.println("➕ Creating new JWT user for tenant ID: " + finalTenantId);
                        User newUser = new User();
                        newUser.setEmail(email);
                        newUser.setUsername(email);
                        newUser.setFirstName(firstName);
                        newUser.setLastName(lastName);
                        newUser.setRole("ROLE_USER");
                        newUser.setEnabled(true);
                        newUser.setTenant(tenant);
                        newUser.setPassword(""); // JWT users don't need password
                        newUser.setCreatedAt(LocalDateTime.now());
                        newUser.setUpdatedAt(LocalDateTime.now());
                        return newUser;
                    });

            user.setUpdatedAt(LocalDateTime.now());
            userRepository.save(user);
            System.out.println("💾 User saved - ID: " + user.getId() + ", Email: " + user.getEmail() + ", Role: "
                    + user.getRole());

            // ==========================================
            // Create authentication with CustomUserDetails
            // ==========================================
            System.out.println("🔄 Setting up Spring Security authentication");

            CustomUserDetails userDetails = new CustomUserDetails(user);

            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    userDetails.getAuthorities());

            System.out.println("✅ Spring Security authentication created");
            System.out.println("👤 Principal type: " + auth.getPrincipal().getClass().getName());
            System.out.println("👤 Principal username: " + userDetails.getUsername());
            System.out.println("🔐 Authorities: " + userDetails.getAuthorities());

            // ==========================================
            // Create session
            // ==========================================
            System.out.println("🔄 Creating HTTP session");

            HttpSession session = request.getSession(true);
            System.out.println("📝 Session ID BEFORE setting auth: " + session.getId());

            SecurityContextHolder.getContext().setAuthentication(auth);
            session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());

            session.setAttribute("user", user);
            session.setAttribute("isLoggedIn", true);
            session.setAttribute("jwtAuthenticated", true);
            session.setAttribute("jwtToken", token);
            session.setAttribute("jwt_tenant_id", tenantId);
            session.setAttribute("jwt_subdomain", tenant.getSubdomain());
            session.setAttribute("tenantId", tenantId);

            System.out.println("✅ Session created and security context saved");
            System.out.println("📝 Session ID AFTER setting auth: " + session.getId());

            // ==========================================
            // Role-based redirect
            // ==========================================
            String redirectUrl;
            if ("ROLE_ADMIN".equalsIgnoreCase(user.getRole())) {
                redirectUrl = "/tenant-admin/dashboard";
                System.out.println("🔀 Redirecting ADMIN to: " + redirectUrl);
            } else {
                redirectUrl = "/user/dashboard";
                System.out.println("🔀 Redirecting USER to: " + redirectUrl);
            }

            System.out.println("========================================");
            System.out.println("✅ JWT Login Successful!");
            System.out.println("👤 User: " + user.getEmail());
            System.out.println("🏢 Tenant: " + tenant.getName());
            System.out.println("🔐 Role: " + user.getRole());
            System.out.println("🔀 Final Redirect: " + redirectUrl);
            System.out.println("========================================");

            return "redirect:" + redirectUrl;

        } catch (Exception e) {
            System.err.println("========================================");
            System.err.println("❌ JWT Callback Error");
            System.err.println("========================================");
            e.printStackTrace();
            System.err.println("Error Type: " + e.getClass().getName());
            System.err.println("Error Message: " + e.getMessage());
            System.err.println("========================================");

            TenantContext.clear();

            return "redirect:/login?error="
                    + URLEncoder.encode("JWT failed: " + e.getMessage(), StandardCharsets.UTF_8);
        }
    }

    /**
     * Helper method to resolve tenant ID from multiple sources
     */
    private Long resolveTenantId(HttpServletRequest request, String state) {
        // Step 1: Check TenantContext
        System.out.println("🔍 Step 1: Checking TenantContext...");
        Long tenantId = TenantContext.getTenantId();
        String subdomain = TenantContext.getSubdomain();
        System.out.println("📥 TenantContext - ID: " + tenantId + ", Subdomain: " + subdomain);

        // Step 2: Fallback to session
        if (tenantId == null) {
            System.out.println("🔍 Step 2: TenantContext is null, checking HTTP session...");
            HttpSession session = request.getSession(false);
            if (session != null) {
                tenantId = (Long) session.getAttribute("jwt_tenant_id");
                subdomain = (String) session.getAttribute("jwt_subdomain");
                System.out.println("📥 Session attributes - ID: " + tenantId + ", Subdomain: " + subdomain);

                if (tenantId != null) {
                    TenantContext.setTenantId(tenantId);
                    if (subdomain != null) {
                        TenantContext.setSubdomain(subdomain);
                    }
                    System.out.println("✅ Restored TenantContext from session");
                }
            } else {
                System.out.println("⚠️ No HTTP session found");
            }
        }

        // Step 3: Fallback to state parameter
        if (tenantId == null && state != null && !state.isEmpty()) {
            System.out.println("🔍 Step 3: Checking state parameter...");
            try {
                tenantId = Long.parseLong(state);
                System.out.println("📥 State parameter - Tenant ID: " + tenantId);
                TenantContext.setTenantId(tenantId);
                System.out.println("✅ Set TenantContext from state parameter");
            } catch (NumberFormatException e) {
                System.err.println("⚠️ Invalid state parameter (not a number): " + state);
            }
        }

        if (tenantId != null) {
            System.out.println("✅ Final resolved Tenant ID: " + tenantId);
        } else {
            System.err.println("❌ Failed to resolve Tenant ID from any source");
        }

        return tenantId;
    }

    /**
     * Logout from JWT session
     */
    @GetMapping("/logout")
    public String logout(HttpServletRequest request) {
        System.out.println("========================================");
        System.out.println("👋 JWT Logout Initiated");
        System.out.println("========================================");

        HttpSession session = request.getSession(false);
        if (session != null) {
            User user = (User) session.getAttribute("user");
            if (user != null) {
                System.out.println("👤 Logging out user: " + user.getEmail());
                System.out.println("🏢 Tenant: " + (user.getTenant() != null ? user.getTenant().getName() : "N/A"));
            }
            session.invalidate();
            System.out.println("✅ Session invalidated");
        } else {
            System.out.println("ℹ️ No active session found");
        }

        SecurityContextHolder.clearContext();
        System.out.println("✅ Security context cleared");

        TenantContext.clear();
        System.out.println("✅ Tenant context cleared");

        System.out.println("========================================");
        System.out.println("✅ JWT Logout Complete");
        System.out.println("========================================");

        return "redirect:/login?logout";
    }
}