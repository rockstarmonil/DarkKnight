package com.example.darkknight.controller;

import com.example.darkknight.model.User;
import com.example.darkknight.repository.UserRepository;
import com.example.darkknight.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;
import java.util.Map;

@Controller
@RequestMapping("/jwt")
public class JwtSsoController {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;

    public JwtSsoController(JwtUtil jwtUtil, UserRepository userRepository) {
        this.jwtUtil = jwtUtil;
        this.userRepository = userRepository;
    }

    @Value("${miniorange.login.url}")
    private String loginUrl;

    @Value("${miniorange.client.id}")
    private String clientId;

    @Value("${miniorange.redirect.uri}")
    private String redirectUri;

    @Value("${miniorange.client.secret}")
    private String clientSecret;

    /** ✅ Step 1: Redirect user to miniOrange JWT SSO login page */
    @GetMapping("/login")
    public String redirectToMiniOrange() {
        String redirectLink = loginUrl
                + "?client_id=" + clientId
                + "&redirect_uri=" + redirectUri;
        return "redirect:" + redirectLink;
    }

    /** ✅ Step 2: Handle both URL patterns (query or path token) */
    @GetMapping({"/callback", "/callback{token}"})
    public String handleJwtCallback(
            @PathVariable(name = "token", required = false) String pathToken,
            @RequestParam(name = "token", required = false) String queryToken,
            HttpServletRequest request,
            Model model,
            HttpSession session) {

        String token = (queryToken != null) ? queryToken : pathToken;

        System.out.println("🟢 Received raw token: " + token);

        if (token == null || token.isBlank()) {
            model.addAttribute("error", "No token received from miniOrange.");
            return "login";
        }

        try {
            // ✅ Validate JWT using HS256 secret
            Map<String, Object> claims = jwtUtil.validateToken(token, clientSecret);
            System.out.println("✅ JWT Claims: " + claims);

            String email = (String) claims.getOrDefault("email", claims.get("sub"));
            String name = (String) claims.getOrDefault("name", claims.getOrDefault("fullName", email));

            if (email == null || email.isBlank()) {
                model.addAttribute("error", "Token invalid — missing email claim.");
                return "login";
            }

            // ✅ Find or create a local user
            User user = userRepository.findByEmail(email).orElseGet(() -> {
                User newUser = new User();
                newUser.setEmail(email);
                newUser.setFirstName(name != null ? name : "Unknown");
                newUser.setPassword("SSO_USER");
                newUser.setEnabled(true);
                newUser.setRole("ROLE_USER");
                return userRepository.save(newUser);
            });

            // ✅ Set Spring Security Authentication
            var authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
            var auth = new UsernamePasswordAuthenticationToken(user.getEmail(), null, authorities);
            SecurityContextHolder.getContext().setAuthentication(auth);

            // ✅ Persist context & user in session
            session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());
            session.setAttribute("user", user);

            System.out.println("✅ User authenticated successfully: " + user.getEmail());

            // ✅ Redirect to user dashboard
            return "redirect:/jwt/user-dashboard";

        } catch (Exception e) {
            e.printStackTrace();
            model.addAttribute("error", "SSO failed: " + e.getMessage());
            return "login";
        }
    }

    /** ✅ Step 3: Show user dashboard (from session) */
    @GetMapping("/user-dashboard")
    public String showUserDashboard(HttpSession session, Model model) {
        User user = (User) session.getAttribute("user");

        if (user == null) {
            System.out.println("⚠️ No user found in session. Redirecting to login...");
            return "redirect:/login";
        }

        model.addAttribute("user", user);
        return "user-dashboard"; // must match templates/user-dashboard.html
    }
}
