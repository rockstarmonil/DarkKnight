package com.example.darkknight.controller;

import com.example.darkknight.model.Tenant;
import com.example.darkknight.model.TenantSsoConfig;
import com.example.darkknight.model.User;
import com.example.darkknight.repository.TenantRepository;
import com.example.darkknight.repository.UserRepository;
import com.example.darkknight.service.TenantSsoConfigService;
import com.example.darkknight.util.TenantContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

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
     * Uses dynamic tenant-based configuration
     */
    @GetMapping("/oauth/login")
    public String oauthLogin() {
        try {
            Long tenantId = TenantContext.getTenantId();
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

            System.out.println("🚀 Initiating OAuth login for tenant: " + tenantId);

            String url = ssoConfig.getOauthAuthorizationUrl() + "?response_type=code"
                    + "&client_id=" + URLEncoder.encode(ssoConfig.getOauthClientId(), StandardCharsets.UTF_8)
                    + "&redirect_uri=" + URLEncoder.encode(ssoConfig.getOauthRedirectUri(), StandardCharsets.UTF_8)
                    + "&scope=openid%20profile%20email";

            System.out.println("🔗 Redirecting to OAuth provider: " + ssoConfig.getOauthAuthorizationUrl());

            return "redirect:" + url;

        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("❌ OAuth initiation error: " + e.getMessage());
            return "redirect:/login?error=" + URLEncoder.encode(e.getMessage(), StandardCharsets.UTF_8);
        }
    }

    /**
     * Step 2: Callback from OAuth provider after login
     */
    @GetMapping("/oauth/callback")
    public String oauthCallback(@RequestParam(required = false) String code,
                                @RequestParam(required = false) String error,
                                Model model,
                                HttpServletRequest request) {

        if (error != null) {
            System.err.println("❌ OAuth error: " + error);
            model.addAttribute("error", "OAuth Error: " + error);
            return "error";
        }

        if (code == null || code.isEmpty()) {
            System.err.println("❌ No authorization code received");
            model.addAttribute("error", "No authorization code received.");
            return "error";
        }

        try {
            Long tenantId = TenantContext.getTenantId();
            if (tenantId == null) {
                System.err.println("❌ No tenant context in OAuth callback");
                model.addAttribute("error", "Invalid tenant context");
                return "error";
            }

            System.out.println("📥 OAuth callback received for tenant: " + tenantId);

            // Get tenant's OAuth configuration
            TenantSsoConfig ssoConfig = ssoConfigService.getOrCreateSsoConfig(tenantId);

            if (!Boolean.TRUE.equals(ssoConfig.getOauthEnabled())) {
                model.addAttribute("error", "OAuth is not enabled");
                return "error";
            }

            // Get tenant
            Tenant tenant = tenantRepository.findById(tenantId)
                    .orElseThrow(() -> new RuntimeException("Tenant not found"));

            RestTemplate restTemplate = new RestTemplate();

            // 1. Exchange code for access token
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            String body = "grant_type=authorization_code"
                    + "&code=" + code
                    + "&redirect_uri=" + URLEncoder.encode(ssoConfig.getOauthRedirectUri(), StandardCharsets.UTF_8)
                    + "&client_id=" + ssoConfig.getOauthClientId()
                    + "&client_secret=" + ssoConfig.getOauthClientSecret();

            HttpEntity<String> requestEntity = new HttpEntity<>(body, headers);
            ResponseEntity<String> tokenResponse = restTemplate.exchange(
                    ssoConfig.getOauthTokenUrl(),
                    HttpMethod.POST,
                    requestEntity,
                    String.class
            );

            JSONObject tokenJson = new JSONObject(tokenResponse.getBody());
            String accessToken = tokenJson.optString("access_token", null);

            if (accessToken == null) {
                System.err.println("❌ No access token received");
                model.addAttribute("error", "No access token received.");
                return "error";
            }

            System.out.println("✅ Access token received");

            // 2. Fetch user info
            HttpHeaders userHeaders = new HttpHeaders();
            userHeaders.setBearerAuth(accessToken);
            HttpEntity<Void> userRequest = new HttpEntity<>(userHeaders);

            ResponseEntity<String> userResponse = restTemplate.exchange(
                    ssoConfig.getOauthUserinfoUrl(),
                    HttpMethod.GET,
                    userRequest,
                    String.class
            );

            JSONObject userInfo = new JSONObject(userResponse.getBody());
            String email = userInfo.optString("email", null);
            String name = userInfo.optString("name", "OAuth User");
            String firstName = userInfo.optString("given_name", userInfo.optString("firstName", name));
            String lastName = userInfo.optString("family_name", userInfo.optString("lastName", ""));

            if (email == null || email.isEmpty()) {
                System.err.println("❌ No email in OAuth response");
                model.addAttribute("error", "No email received from OAuth provider");
                return "error";
            }

            System.out.println("👤 OAuth user email: " + email);

            // 3. Find or create user for this tenant
            User user = userRepository.findByEmailAndTenantId(email, tenantId)
                    .orElseGet(() -> {
                        System.out.println("➕ Creating new OAuth user: " + email);
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
            System.out.println("💾 OAuth user saved: " + user.getEmail());

            // 4. Create session
            HttpSession session = request.getSession(true);
            session.setAttribute("isLoggedIn", true);
            session.setAttribute("user", user);
            session.setAttribute("oauthAuthenticated", true);
            session.setAttribute("accessToken", accessToken);

            // 5. Setup Spring Security
            List<SimpleGrantedAuthority> authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority(user.getRole()));

            var auth = new UsernamePasswordAuthenticationToken(
                    email, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(auth);
            session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());

            System.out.println("✅ OAuth login successful for: " + email);

            // Redirect based on role
            String redirectUrl = "/dashboard";
            if ("ROLE_ADMIN".equals(user.getRole())) {
                redirectUrl = "/tenant-admin/dashboard";
            }

            return "redirect:" + redirectUrl;

        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("❌ OAuth callback error: " + e.getMessage());
            model.addAttribute("error", "OAuth Exception: " + e.getMessage());
            return "error";
        }
    }

    /**
     * Logout
     */
    @GetMapping("/oauth/logout")
    public String logout(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            User user = (User) session.getAttribute("user");
            if (user != null) {
                System.out.println("👋 Logging out OAuth user: " + user.getEmail());
            }
            session.invalidate();
        }
        SecurityContextHolder.clearContext();
        System.out.println("✅ OAuth logout successful");
        return "redirect:/login?logout";
    }
}