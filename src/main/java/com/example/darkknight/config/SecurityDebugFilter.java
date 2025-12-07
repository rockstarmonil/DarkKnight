package com.example.darkknight.config;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class SecurityDebugFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String uri = httpRequest.getRequestURI();
        
        if (uri.startsWith("/user/") || uri.startsWith("/tenant-admin/")) {
            System.out.println("========================================");
            System.out.println("🔍 SECURITY DEBUG FILTER");
            System.out.println("========================================");
            System.out.println("📍 URI: " + uri);
            System.out.println("🔐 Session ID: " + httpRequest.getSession(false) != null ? httpRequest.getSession().getId() : "NO SESSION");
            
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            System.out.println("👤 Authentication: " + (auth != null ? "Present" : "NULL"));
            
            if (auth != null) {
                System.out.println("   - Principal: " + auth.getPrincipal().getClass().getSimpleName());
                System.out.println("   - Authenticated: " + auth.isAuthenticated());
                System.out.println("   - Authorities: " + auth.getAuthorities());
            }
            System.out.println("========================================");
        }
        
        chain.doFilter(request, response);
    }
}