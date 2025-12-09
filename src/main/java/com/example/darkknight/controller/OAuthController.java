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
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;

@Controller
public class OAuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private TenantSsoConfigService ssoConfigService;

    /**
     * Step 1: Redirect to OAuth provider login
     */
    @GetMapping("/oauth/login")
    public String oauthLogin(HttpServletRequest request) {
        try {
            Long tenantId = TenantContext.getTenantId();
            String subdomain = TenantContext.getSubdomain();
            
            System.out.println("========================================");
            System.out.println("🚀 OAuth Login Initiated");
            System.out.println("========================================");
            System.out.println("📍 Tenant ID: " + tenantId);
            System.out.println("📍 Subdomain: " + subdomain);
            
            if (tenantId == null) {
                System.err.println("❌ No tenant context found");
                return "redirect:/login?error=no_tenant";
            }

            // Get tenant's OAuth configuration
            TenantSsoConfig ssoConfig = ssoConfigService.getOrCreateSsoConfig(tenantId);

            // Check if OAuth is enabled
            if (!Boolean.TRUE.equals(ssoConfig.getOauthEnabled())) {
                System.err.println("❌ OAuth is not enabled for this tenant");
                return "redirect:/login?error=oauth_disabled";
            }

            // Validate OAuth configuration
            if (!ssoConfigService.validateOauthConfig(ssoConfig)) {
                System.err.println("❌ OAuth configuration is incomplete");
                return "redirect:/login?error=oauth_not_configured";
            }

            // Store tenant context in session for callback
            HttpSession session = request.getSession(true);
            session.setAttribute("oauth_tenant_id", tenantId);
            session.setAttribute("oauth_subdomain", subdomain);
            
            System.out.println("💾 Stored in session:");
            System.out.println("   - Tenant ID: " + tenantId);
            System.out.println("   - Subdomain: " + subdomain);

            String authUrl = ssoConfig.getOauthAuthorizationUrl() + "?response_type=code"
                    + "&client_id=" + URLEncoder.encode(ssoConfig.getOauthClientId(), StandardCharsets.UTF_8)
                    + "&redirect_uri=" + URLEncoder.encode(ssoConfig.getOauthRedirectUri(), StandardCharsets.UTF_8)
                    + "&scope=openid%20profile%20email"
                    + "&state=" + tenantId;

            System.out.println("🔗 Authorization URL: " + ssoConfig.getOauthAuthorizationUrl());
            System.out.println("🔗 Redirect URI: " + ssoConfig.getOauthRedirectUri());
            System.out.println("🔗 Client ID: " + ssoConfig.getOauthClientId());
            System.out.println("========================================");

            return "redirect:" + authUrl;

        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("❌ OAuth initiation error: " + e.getMessage());
            return "redirect:/login?error=" + URLEncoder.encode(e.getMessage(), StandardCharsets.UTF_8);
        }
    }

    /**
     * Step 2: Callback from OAuth provider
     */
    @GetMapping("/oauth/callback")
    public String oauthCallback(@RequestParam(required = false) String code,
                                @RequestParam(required = false) String error,
                                @RequestParam(required = false) String state,
                                HttpServletRequest request) {

        System.out.println("========================================");
        System.out.println("🔔 OAuth Callback Received");
        System.out.println("========================================");
        System.out.println("📝 Code: " + (code != null ? "present (length: " + code.length() + ")" : "null"));
        System.out.println("📝 Error: " + error);
        System.out.println("📝 State: " + state);

        if (error != null) {
            System.err.println("❌ OAuth provider returned error: " + error);
            return "redirect:/login?error=" + URLEncoder.encode("OAuth Error: " + error, StandardCharsets.UTF_8);
        }

        if (code == null || code.isEmpty()) {
            System.err.println("❌ No authorization code received from OAuth provider");
            return "redirect:/login?error=no_code";
        }

        try {
            // Resolve tenant context from multiple sources
            Long tenantId = resolveTenantId(request, state);
            
            if (tenantId == null) {
                System.err.println("❌ Could not determine tenant context");
                return "redirect:/login?error=no_tenant_context";
            }

            System.out.println("✅ Tenant Context Resolved - ID: " + tenantId);

            // Get tenant and config
            Tenant tenant = tenantRepository.findById(tenantId)
                    .orElseThrow(() -> new RuntimeException("Tenant not found: " + tenantId));
            
            TenantSsoConfig ssoConfig = ssoConfigService.getOrCreateSsoConfig(tenantId);

            if (!Boolean.TRUE.equals(ssoConfig.getOauthEnabled())) {
                System.err.println("❌ OAuth is not enabled for tenant: " + tenantId);
                return "redirect:/login?error=oauth_not_enabled";
            }

            System.out.println("🏢 Tenant: " + tenant.getName() + " (ID: " + tenant.getId() + ")");

            RestTemplate restTemplate = new RestTemplate();

            // ==========================================
            // 1. Exchange code for access token
            // ==========================================
            System.out.println("🔄 Step 1: Exchanging authorization code for access token");
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            String body = "grant_type=authorization_code"
                    + "&code=" + code
                    + "&redirect_uri=" + URLEncoder.encode(ssoConfig.getOauthRedirectUri(), StandardCharsets.UTF_8)
                    + "&client_id=" + ssoConfig.getOauthClientId()
                    + "&client_secret=" + ssoConfig.getOauthClientSecret();

            System.out.println("🔗 Token URL: " + ssoConfig.getOauthTokenUrl());

            HttpEntity<String> requestEntity = new HttpEntity<>(body, headers);
            ResponseEntity<String> tokenResponse = restTemplate.exchange(
                    ssoConfig.getOauthTokenUrl(),
                    HttpMethod.POST,
                    requestEntity,
                    String.class
            );

            System.out.println("📨 Token response status: " + tokenResponse.getStatusCode());

            JSONObject tokenJson = new JSONObject(tokenResponse.getBody());
            String accessToken = tokenJson.optString("access_token", null);

            if (accessToken == null) {
                System.err.println("❌ No access token in response");
                System.err.println("Response body: " + tokenResponse.getBody());
                return "redirect:/login?error=no_access_token";
            }

            System.out.println("✅ Access token received successfully");

            // ==========================================
            // 2. Fetch user info
            // ==========================================
            System.out.println("🔄 Step 2: Fetching user information");
            
            HttpHeaders userHeaders = new HttpHeaders();
            userHeaders.setBearerAuth(accessToken);
            HttpEntity<Void> userRequest = new HttpEntity<>(userHeaders);

            System.out.println("🔗 User Info URL: " + ssoConfig.getOauthUserinfoUrl());

            ResponseEntity<String> userResponse = restTemplate.exchange(
                    ssoConfig.getOauthUserinfoUrl(),
                    HttpMethod.GET,
                    userRequest,
                    String.class
            );

            System.out.println("📨 User info response status: " + userResponse.getStatusCode());
            System.out.println("📄 User info body: " + userResponse.getBody());

            JSONObject userInfo = new JSONObject(userResponse.getBody());
            String email = userInfo.optString("email", null);
            String name = userInfo.optString("name", "OAuth User");
            String firstName = userInfo.optString("given_name", userInfo.optString("firstName", name.split(" ")[0]));
            String lastName = userInfo.optString("family_name", userInfo.optString("lastName", name.split(" ").length > 1 ? name.split(" ")[1] : ""));

            if (email == null || email.isEmpty()) {
                System.err.println("❌ No email in OAuth user info response");
                return "redirect:/login?error=no_email";
            }

            System.out.println("👤 OAuth User - Email: " + email + ", Name: " + firstName + " " + lastName);

            // ==========================================
            // 3. Find or create user for this tenant
            // ==========================================
            System.out.println("🔄 Step 3: Finding or creating user");
            
            final Long finalTenantId = tenantId; // Make effectively final for lambda
            User user = userRepository.findByEmailAndTenantId(email, tenantId)
                    .orElseGet(() -> {
                        System.out.println("➕ Creating new OAuth user for tenant ID: " + finalTenantId);
                        User newUser = new User();
                        newUser.setEmail(email);
                        newUser.setUsername(email);
                        newUser.setFirstName(firstName);
                        newUser.setLastName(lastName);
                        newUser.setRole("ROLE_USER");
                        newUser.setEnabled(true);
                        newUser.setTenant(tenant);
                        newUser.setPassword(""); // OAuth users don't need password
                        newUser.setCreatedAt(LocalDateTime.now());
                        newUser.setUpdatedAt(LocalDateTime.now());
                        return newUser;
                    });

            user.setUpdatedAt(LocalDateTime.now());
            userRepository.save(user);
            System.out.println("💾 User saved - ID: " + user.getId() + ", Email: " + user.getEmail() + ", Role: " + user.getRole());

            // ==========================================
            // 4. Create CustomUserDetails and Authentication
            // ==========================================
            System.out.println("🔄 Step 4: Setting up Spring Security authentication");

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
            // 5. Create session and save security context
            // ==========================================
            System.out.println("🔄 Step 5: Creating HTTP session and saving security context");

            // Get or create session
            HttpSession session = request.getSession(true);
            System.out.println("📝 Session ID BEFORE setting auth: " + session.getId());

            // Set authentication in SecurityContext
            SecurityContextHolder.getContext().setAuthentication(auth);

            // ⭐ CRITICAL: Explicitly save security context to session
            session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());

            // Store tenant info in session for subsequent requests
            session.setAttribute("user", user);
            session.setAttribute("isLoggedIn", true);
            session.setAttribute("oauthAuthenticated", true);
            session.setAttribute("accessToken", accessToken);
            session.setAttribute("oauth_tenant_id", tenantId);
            session.setAttribute("oauth_subdomain", tenant.getSubdomain());
            session.setAttribute("tenantId", tenantId);

            System.out.println("✅ Session created and security context saved");
            System.out.println("📝 Session ID AFTER setting auth: " + session.getId());
            System.out.println("🔐 Security context in session: " + (session.getAttribute("SPRING_SECURITY_CONTEXT") != null));

            // ==========================================
            // 6. Role-based redirect (exactly like AuthController)
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
            System.out.println("✅ OAuth Login Successful!");
            System.out.println("👤 User: " + user.getEmail());
            System.out.println("🏢 Tenant: " + tenant.getName());
            System.out.println("🔐 Role: " + user.getRole());
            System.out.println("🔀 Final Redirect: " + redirectUrl);
            System.out.println("========================================");

            return "redirect:" + redirectUrl;

        } catch (Exception e) {
            System.err.println("========================================");
            System.err.println("❌ OAuth Callback Error");
            System.err.println("========================================");
            e.printStackTrace();
            System.err.println("Error Type: " + e.getClass().getName());
            System.err.println("Error Message: " + e.getMessage());
            System.err.println("========================================");
            
            // Clear tenant context on error
            TenantContext.clear();
            
            return "redirect:/login?error=" + URLEncoder.encode("OAuth failed: " + e.getMessage(), StandardCharsets.UTF_8);
        } finally {
            System.out.println("🔚 OAuth callback processing complete");
        }
    }

    /**
     * Helper method to resolve tenant ID from multiple sources
     */
    private Long resolveTenantId(HttpServletRequest request, String state) {
        // Step 1: Check TenantContext (set by TenantInterceptor)
        System.out.println("🔍 Step 1: Checking TenantContext...");
        Long tenantId = TenantContext.getTenantId();
        String subdomain = TenantContext.getSubdomain();
        System.out.println("📥 TenantContext - ID: " + tenantId + ", Subdomain: " + subdomain);

        // Step 2: Fallback to session
        if (tenantId == null) {
            System.out.println("🔍 Step 2: TenantContext is null, checking HTTP session...");
            HttpSession session = request.getSession(false);
            if (session != null) {
                tenantId = (Long) session.getAttribute("oauth_tenant_id");
                subdomain = (String) session.getAttribute("oauth_subdomain");
                System.out.println("📥 Session attributes - ID: " + tenantId + ", Subdomain: " + subdomain);
                
                // Restore to TenantContext
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
     * Logout from OAuth session
     */
    @GetMapping("/oauth/logout")
    public String logout(HttpServletRequest request) {
        System.out.println("========================================");
        System.out.println("👋 OAuth Logout Initiated");
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
        System.out.println("✅ OAuth Logout Complete");
        System.out.println("========================================");
        
        return "redirect:/login?logout";
    }
}