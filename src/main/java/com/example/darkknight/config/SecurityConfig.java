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
                .csrf(csrf -> csrf
                        // Disable CSRF for OAuth/SAML/JWT callback endpoints
                        .ignoringRequestMatchers(
                                "/oauth/**",
                                "/sso/**",
                                "/jwt/**",
                                "/login",
                                "/api/**"
                        )
                )
                .authorizeHttpRequests(auth -> auth
                        // ✅ Public Routes (Permit All)
                        .requestMatchers(
                                "/jwt/**",              // JWT SSO endpoints
                                "/sso/saml/**",         // SAML SSO endpoints
                                "/sso/oauth/**",        // OAuth SSO endpoints
                                "/oauth/**",            // OAuth callback and endpoints
                                "/oauth/login",         // OAuth login initiation
                                "/oauth/callback",      // OAuth callback
                                "/tenant/register",     // Tenant registration
                                "/tenant/check-subdomain", // Subdomain availability check
                                "/login",
                                "/register",
                                "/api/auth/register",
                                "/css/**",
                                "/js/**",
                                "/images/**",
                                "/error",
                                "/"
                        ).permitAll()

                        // ✅ Protected Routes - Super Admin
                        .requestMatchers("/main-admin/**").hasAuthority("ROLE_SUPER_ADMIN")

                        // ✅ Protected Routes - Tenant Admin
                        .requestMatchers("/admin/**").hasAuthority("ROLE_ADMIN")
                        .requestMatchers("/tenant-admin/**").hasAuthority("ROLE_ADMIN")

                        // ✅ Protected Routes - Users
                        .requestMatchers("/user/**").hasAnyAuthority("ROLE_USER", "ROLE_ADMIN")

                        // Dashboard redirects
                        .requestMatchers("/dashboard").authenticated()

                        // Any other request must be authenticated
                        .anyRequest().authenticated()
                )

                // ✅ Disable default form login (we handle login manually)
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/spring-security-login")
                        .permitAll()
                        .disable()
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