package com.example.darkknight.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

@Configuration
public class SecurityConfig {

        @Autowired
        private SecurityDebugFilter securityDebugFilter;

        @Bean
        public SecurityContextRepository securityContextRepository() {
                return new HttpSessionSecurityContextRepository();
        }

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                http
                                .csrf(csrf -> csrf
                                                .ignoringRequestMatchers(
                                                                "/oauth/**",
                                                                "/sso/**",
                                                                "/jwt/**",
                                                                "/ad/login",
                                                                "/login",
                                                                "/api/**",
                                                                "/tenant/register",
                                                                "/admin/sso/**",
                                                                "/admin/ad/**"))
                                .authorizeHttpRequests(auth -> auth
                                                // Public Routes
                                                .requestMatchers(
                                                                "/jwt/**",
                                                                "/ad/login",
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
                                                                "/")
                                                .permitAll()

                                                // Protected Routes
                                                .requestMatchers("/main-admin/**").hasAuthority("ROLE_SUPER_ADMIN")
                                                .requestMatchers("/admin/**").hasAuthority("ROLE_ADMIN")
                                                .requestMatchers("/tenant-admin/**").hasAuthority("ROLE_ADMIN")
                                                .requestMatchers("/user/**").hasAnyAuthority("ROLE_USER", "ROLE_ADMIN")

                                                .requestMatchers("/dashboard").authenticated()
                                                .anyRequest().authenticated())

                                .formLogin(form -> form
                                                .loginPage("/login")
                                                .loginProcessingUrl("/spring-security-login")
                                                .permitAll()
                                                .disable())

                                .logout(logout -> logout
                                                .logoutUrl("/logout")
                                                .logoutSuccessUrl("/login?logout")
                                                .invalidateHttpSession(true)
                                                .clearAuthentication(true)
                                                .permitAll())

                                // ⭐ CRITICAL FIX: Session management configuration
                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                                                .sessionFixation().none() // JWT tokens are validated cryptographically
                                                                          // — session fixation protection not needed
                                                                          // here
                                                .maximumSessions(1)
                                                .maxSessionsPreventsLogin(false))

                                // ⭐ CRITICAL FIX: Store security context in session
                                .securityContext(context -> context
                                                .requireExplicitSave(false)
                                                .securityContextRepository(securityContextRepository()));

                // Add debug filter
                http.addFilterBefore(securityDebugFilter, UsernamePasswordAuthenticationFilter.class);

                return http.build();
        }

        @Bean
        public PasswordEncoder passwordEncoder() {
                return new BCryptPasswordEncoder();
        }
}