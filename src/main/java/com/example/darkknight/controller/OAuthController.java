package com.example.darkknight.controller;

import com.example.darkknight.model.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
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
import java.util.Collections;

@Controller
public class OAuthController {

    @Value("${miniorange.oauth.client.id}")
    private String clientId;

    @Value("${miniorange.oauth.client.secret}")
    private String clientSecret;

    @Value("${miniorange.oauth.redirect.uri}")
    private String redirectUri;

    @Value("${miniorange.oauth.authorization.url}")
    private String authorizeUrl;

    @Value("${miniorange.oauth.token.url}")
    private String tokenUrl;

    @Value("${miniorange.oauth.userinfo.url}")
    private String userInfoUrl;

    // 🔹 Step 1: Redirect to miniOrange login
    @GetMapping("/sso/oauth/login")
    public String oauthLogin() {
        String url = authorizeUrl + "?response_type=code"
                + "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
                + "&scope=openid%20profile%20email";
        return "redirect:" + url;
    }

    // 🔹 Step 2: Callback from miniOrange after login
    @GetMapping("/oauth/callback")
    public String oauthCallback(@RequestParam(required = false) String code,
                                @RequestParam(required = false) String error,
                                Model model,
                                HttpServletRequest request) {

        if (error != null) {
            model.addAttribute("error", "OAuth Error: " + error);
            return "error";
        }

        if (code == null || code.isEmpty()) {
            model.addAttribute("error", "No authorization code received.");
            return "error";
        }

        try {
            RestTemplate restTemplate = new RestTemplate();

            // 1️⃣ Exchange code for access token
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            String body = "grant_type=authorization_code"
                    + "&code=" + code
                    + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
                    + "&client_id=" + clientId
                    + "&client_secret=" + clientSecret;

            HttpEntity<String> requestEntity = new HttpEntity<>(body, headers);
            ResponseEntity<String> tokenResponse = restTemplate.exchange(
                    tokenUrl,
                    HttpMethod.POST,
                    requestEntity,
                    String.class
            );

            JSONObject tokenJson = new JSONObject(tokenResponse.getBody());
            String accessToken = tokenJson.optString("access_token", null);

            if (accessToken == null) {
                model.addAttribute("error", "No access token received.");
                return "error";
            }

            // 2️⃣ Fetch user info
            HttpHeaders userHeaders = new HttpHeaders();
            userHeaders.setBearerAuth(accessToken);
            HttpEntity<Void> userRequest = new HttpEntity<>(userHeaders);

            ResponseEntity<String> userResponse = restTemplate.exchange(
                    userInfoUrl,
                    HttpMethod.GET,
                    userRequest,
                    String.class
            );

            JSONObject userInfo = new JSONObject(userResponse.getBody());
            String email = userInfo.optString("email", "unknown@example.com");
            String name = userInfo.optString("name", "User");

            // 3️⃣ Create User object
            User user = new User();
            user.setUsername(email);
            user.setEmail(email);
            user.setFirstName(name);
            user.setEnabled(true);
            user.setCreatedAt(LocalDateTime.now().minusDays(10)); // dummy date
            user.setUpdatedAt(LocalDateTime.now());

            // 4️⃣ Create session
            HttpSession session = request.getSession(true);
            session.setAttribute("isLoggedIn", true);
            session.setAttribute("user", user);
            session.setAttribute("accessToken", accessToken);

            // 5️⃣ Register Spring Security context
            var authority = new SimpleGrantedAuthority("ROLE_USER");
            var auth = new UsernamePasswordAuthenticationToken(email, null, Collections.singletonList(authority));
            SecurityContextHolder.getContext().setAuthentication(auth);
            session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());

            System.out.println("✅ OAuth login successful for: " + email);
            return "redirect:/user-dashboard";

        } catch (Exception e) {
            e.printStackTrace();
            model.addAttribute("error", "OAuth Exception: " + e.getMessage());
            return "error";
        }
    }

    // 🔹 Step 3: Dashboard view
    @GetMapping("/user-dashboard")
    public String userDashboard(HttpServletRequest request, Model model) {
        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute("isLoggedIn") == null) {
            return "redirect:/login";
        }

        User user = (User) session.getAttribute("user");
        if (user == null) {
            return "redirect:/login";
        }

        model.addAttribute("user", user);
        return "user-dashboard";
    }

    // 🔹 Step 4: Logout
    @GetMapping("/logout")
    public String logout(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        SecurityContextHolder.clearContext();
        return "redirect:/login?logout";
    }

    // 🔹 Step 5: For testing config
    @GetMapping("/sso/oauth/test")
    public String testOAuth(Model model) {
        model.addAttribute("clientId", clientId);
        model.addAttribute("redirectUri", redirectUri);
        model.addAttribute("authorizeUrl", authorizeUrl);
        return "login";
    }
}
