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
                        // ✅ Public Routes (Permit All)
                        .requestMatchers(
                                "/jwt/**",              // JWT SSO endpoints
                                "/sso/saml/**",         // SAML SSO endpoints
                                "/sso/oauth/**",        // OAuth SSO endpoints
                                "/oauth/**",            // OAuth callback
                                "/tenant/register",     // Tenant registration
                                "/tenant/check-subdomain", // Subdomain availability check
                                "/login",               // ✅ Login page and POST handled by AuthController
                                "/register",
                                "/api/auth/register",
                                "/css/**",
                                "/js/**",
                                "/images/**",
                                "/error",
                                "/"
                        ).permitAll()

                        // ✅ Protected Routes - Role-based access
                        .requestMatchers("/main-admin/**").hasAuthority("ROLE_SUPER_ADMIN")
                        .requestMatchers("/admin/**").hasAuthority("ROLE_ADMIN")
                        .requestMatchers("/tenant-admin/**").hasAuthority("ROLE_ADMIN")
                        .requestMatchers("/user/**").hasAnyAuthority("ROLE_USER", "ROLE_ADMIN")

                        // Dashboard redirects
                        .requestMatchers("/dashboard").authenticated()

                        // Any other request must be authenticated
                        .anyRequest().authenticated()
                )

                // ✅ CRITICAL FIX: Disable default form login since we handle it manually
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/spring-security-login") // ✅ Dummy URL - never used
                        .permitAll()
                        .disable() // ✅ Disable Spring Security's form login processing
                )

                // ✅ Logout setup
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout")
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .permitAll()
                )

                // ✅ Session management
                .sessionManagement(session -> session
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false)
                );

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}