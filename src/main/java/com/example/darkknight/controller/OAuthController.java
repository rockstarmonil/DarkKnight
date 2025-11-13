package com.example.darkknight.controller;

import com.example.darkknight.model.User;
import com.example.darkknight.repository.UserRepository;
import com.example.darkknight.security.CustomUserDetails;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.*;

import java.util.*;

@Controller
@RequestMapping("/oauth")
public class OAuthController {

    @Autowired
    private UserRepository userRepository;

    @Value("${miniorange.oauth.client.id}")
    private String clientId;

    @Value("${miniorange.oauth.client.secret}")
    private String clientSecret;

    @Value("${miniorange.oauth.authorization.url}")
    private String authorizationUrl;

    @Value("${miniorange.oauth.token.url}")
    private String tokenUrl;

    @Value("${miniorange.oauth.userinfo.url}")
    private String userinfoUrl;

    @Value("${miniorange.oauth.redirect.uri}")
    private String redirectUri;

    /**
     * Initiate OAuth login - redirects user to OAuth provider
     */
    @GetMapping("/login")
    public String initiateOAuthLogin(HttpServletRequest request) {
        System.out.println("🔐 Initiating OAuth login");
        System.out.println("   - Authorization URL: " + authorizationUrl);
        System.out.println("   - Client ID: " + clientId);
        System.out.println("   - Redirect URI: " + redirectUri);

        // Build OAuth authorization URL
        String authUrl = authorizationUrl +
                "?client_id=" + clientId +
                "&redirect_uri=" + redirectUri +
                "&response_type=code" +
                "&scope=openid email profile";

        System.out.println("🔗 Redirecting to: " + authUrl);

        return "redirect:" + authUrl;
    }

    /**
     * OAuth callback - handles the response from OAuth provider
     */
    @GetMapping("/callback")
    public String handleOAuthCallback(
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String error,
            @RequestParam(required = false) String error_description,
            HttpServletRequest request) {

        System.out.println("📥 OAuth callback received");
        System.out.println("   - Code: " + (code != null ? "Present" : "Missing"));
        System.out.println("   - Error: " + error);

        // Check for OAuth errors
        if (error != null) {
            System.err.println("❌ OAuth error: " + error);
            System.err.println("   Description: " + error_description);
            return "redirect:/login?error=oauth_failed&message=" + error_description;
        }

        // Check if authorization code is present
        if (code == null || code.isEmpty()) {
            System.err.println("❌ No authorization code received");
            return "redirect:/login?error=no_code";
        }

        try {
            // Step 1: Exchange authorization code for access token
            System.out.println("🔄 Exchanging code for access token");
            String accessToken = exchangeCodeForToken(code);

            if (accessToken == null) {
                System.err.println("❌ Failed to get access token");
                return "redirect:/login?error=token_failed";
            }

            System.out.println("✅ Access token received");

            // Step 2: Get user info using access token
            System.out.println("🔄 Fetching user info");
            Map<String, Object> userInfo = getUserInfo(accessToken);

            if (userInfo == null || userInfo.isEmpty()) {
                System.err.println("❌ Failed to get user info");
                return "redirect:/login?error=userinfo_failed";
            }

            System.out.println("✅ User info received: " + userInfo);

            // Step 3: Extract user details
            String email = (String) userInfo.get("email");
            String firstName = (String) userInfo.get("given_name");
            String lastName = (String) userInfo.get("family_name");

            if (email == null || email.isEmpty()) {
                System.err.println("❌ No email in user info");
                return "redirect:/login?error=no_email";
            }

            System.out.println("📧 User email: " + email);

            // Step 4: Find or create user
            User user = userRepository.findByEmail(email).orElse(null);

            if (user == null) {
                System.out.println("⚠️ User not found, OAuth users must be pre-registered");
                return "redirect:/login?error=user_not_found";
            }

            // Check if user is enabled
            if (!user.isEnabled()) {
                System.err.println("❌ User account is disabled: " + email);
                return "redirect:/login?error=account_disabled";
            }

            System.out.println("✅ User authenticated via OAuth: " + email);

            // Step 5: Create authentication and session
            CustomUserDetails userDetails = new CustomUserDetails(user);
            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                    userDetails, null, userDetails.getAuthorities());

            SecurityContextHolder.getContext().setAuthentication(auth);

            HttpSession session = request.getSession(true);
            session.setAttribute("user", user);
            session.setAttribute("isLoggedIn", true);
            session.setAttribute("oauthLogin", true);
            session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());

            System.out.println("✅ OAuth login successful for: " + email);

            // Step 6: Redirect based on role
            if ("ROLE_ADMIN".equalsIgnoreCase(user.getRole())) {
                return "redirect:/tenant-admin/dashboard";
            } else {
                return "redirect:/user/dashboard";
            }

        } catch (Exception e) {
            System.err.println("❌ OAuth callback error: " + e.getMessage());
            e.printStackTrace();
            return "redirect:/login?error=oauth_exception";
        }
    }

    /**
     * Exchange authorization code for access token
     */
    private String exchangeCodeForToken(String code) {
        try {
            RestTemplate restTemplate = new RestTemplate();

            // Prepare token request
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            String requestBody = "grant_type=authorization_code" +
                    "&code=" + code +
                    "&redirect_uri=" + redirectUri +
                    "&client_id=" + clientId +
                    "&client_secret=" + clientSecret;

            HttpEntity<String> request = new HttpEntity<>(requestBody, headers);

            System.out.println("🔄 Token request to: " + tokenUrl);

            // Make token request
            ResponseEntity<Map> response = restTemplate.exchange(
                    tokenUrl,
                    HttpMethod.POST,
                    request,
                    Map.class
            );

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                Map<String, Object> tokenResponse = response.getBody();
                String accessToken = (String) tokenResponse.get("access_token");
                System.out.println("✅ Access token retrieved");
                return accessToken;
            }

            System.err.println("❌ Token request failed: " + response.getStatusCode());
            return null;

        } catch (Exception e) {
            System.err.println("❌ Error exchanging code for token: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Get user info using access token
     */
    private Map<String, Object> getUserInfo(String accessToken) {
        try {
            RestTemplate restTemplate = new RestTemplate();

            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);

            HttpEntity<String> request = new HttpEntity<>(headers);

            System.out.println("🔄 Userinfo request to: " + userinfoUrl);

            ResponseEntity<Map> response = restTemplate.exchange(
                    userinfoUrl,
                    HttpMethod.GET,
                    request,
                    Map.class
            );

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                System.out.println("✅ User info retrieved");
                return response.getBody();
            }

            System.err.println("❌ Userinfo request failed: " + response.getStatusCode());
            return null;

        } catch (Exception e) {
            System.err.println("❌ Error getting user info: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
}