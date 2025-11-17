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
                        // Disable CSRF for OAuth/SAML/JWT callback endpoints + Tenant Registration
                        .ignoringRequestMatchers(
                                "/oauth/**",
                                "/sso/**",
                                "/jwt/**",
                                "/login",
                                "/api/**",
                                "/tenant/register",  // ✅ ADDED THIS LINE
                                "/admin/sso/save-oauth"   // ✅ FIXED
                        )
                )
                .authorizeHttpRequests(auth -> auth
                        // Public Routes
                        .requestMatchers(
                                "/jwt/**",
                                "/sso/saml/**",
                                "/sso/oauth/**",
                                "/oauth/**",
                                "/oauth/login",
                                "/oauth/callback",
                                "/tenant/register",
                                "/tenant/check-subdomain",
                                "/login",
                                "/register",
                                "/api/auth/register",
                                "/css/**",
                                "/js/**",
                                "/images/**",
                                "/error",
                                "/"
                        ).permitAll()

                        // Protected Routes
                        .requestMatchers("/main-admin/**").hasAuthority("ROLE_SUPER_ADMIN")
                        .requestMatchers("/admin/**").hasAuthority("ROLE_ADMIN")
                        .requestMatchers("/tenant-admin/**").hasAuthority("ROLE_ADMIN")
                        .requestMatchers("/user/**").hasAnyAuthority("ROLE_USER", "ROLE_ADMIN")

                        .requestMatchers("/dashboard").authenticated()
                        .anyRequest().authenticated()
                )

                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/spring-security-login")
                        .permitAll()
                        .disable()
                )

                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout")
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .permitAll()
                )

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
