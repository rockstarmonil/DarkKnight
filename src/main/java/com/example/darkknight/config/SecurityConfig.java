package com.example.darkknight.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        // ✅ Public routes (OAuth, JWT, SAML, etc.)
                        .requestMatchers(
                                "/jwt/**",              // JWT SSO endpoints
                                "/sso/saml/**",         // SAML SSO endpoints
                                "/sso/oauth/**",        // OAuth SSO endpoints
                                "/oauth/**",            // OAuth callback
                                "/tenant/register",     // Tenant registration
                                "/tenant/check-subdomain", // Subdomain availability check
                                "/login",
                                "/register",
                                "/api/auth/register",
                                "/css/**",
                                "/js/**",
                                "/images/**",
                                "/main-admin/**"        // Super admin dashboard and CRUD
                        ).permitAll()

                        // ✅ Protected routes
                        .requestMatchers("/admin/**").hasAuthority("ROLE_ADMIN")
                        .requestMatchers("/tenant-admin/**").hasAuthority("ROLE_ADMIN")  // ✅ NEW: Tenant admin CRUD
                        .requestMatchers("/user/**").hasAuthority("ROLE_USER")
                        .requestMatchers("/user-dashboard").authenticated()
                        .requestMatchers("/dashboard").authenticated()

                        .anyRequest().authenticated()
                )

                // ✅ Standard form login
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/spring-login")  // Changed so manual login works
                        .successHandler(customAuthenticationSuccessHandler())
                        .permitAll()
                )

                // ✅ Logout setup
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout")
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .permitAll()
                )

                // ✅ Session management for SSO
                .sessionManagement(session -> session
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false)
                );

        return http.build();
    }

    // ✅ Redirect based on role for normal login
    @Bean
    public AuthenticationSuccessHandler customAuthenticationSuccessHandler() {
        return (HttpServletRequest request,
                HttpServletResponse response,
                Authentication authentication) -> {

            boolean isAdmin = authentication.getAuthorities().stream()
                    .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));

            if (isAdmin) {
                response.sendRedirect("/admin/dashboard");
            } else {
                response.sendRedirect("/user/dashboard");
            }
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}