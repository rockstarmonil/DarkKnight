package com.example.darkknight.config;

import com.example.darkknight.model.Tenant;
import com.example.darkknight.repository.TenantRepository;
import com.example.darkknight.util.TenantContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Optional;

@Component
public class TenantInterceptor implements HandlerInterceptor {

    @Autowired
    private TenantRepository tenantRepository;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String host = request.getServerName(); // e.g., "acme.localhost" or "localhost"
        String subdomain = extractSubdomain(host);

        System.out.println("🌐 Request Host: " + host);
        System.out.println("🔍 Extracted Subdomain: " + subdomain);

        // Skip tenant resolution for main admin routes
        String requestUri = request.getRequestURI();
        if (requestUri.startsWith("/main-admin") ||
                requestUri.startsWith("/tenant/register") ||
                requestUri.startsWith("/css") ||
                requestUri.startsWith("/js") ||
                requestUri.startsWith("/images")) {
            System.out.println("⚪ Skipping tenant resolution for: " + requestUri);
            return true;
        }

        // If subdomain exists, try to find tenant
        if (subdomain != null && !subdomain.isEmpty()) {
            Optional<Tenant> tenantOpt = tenantRepository.findBySubdomain(subdomain);

            if (tenantOpt.isPresent()) {
                Tenant tenant = tenantOpt.get();

                // Check if tenant is active
                if (!tenant.isActive()) {
                    response.sendRedirect("/error?message=Tenant+is+suspended");
                    return false;
                }

                // Set tenant context
                TenantContext.setTenantId(tenant.getId());
                TenantContext.setSubdomain(subdomain);
                System.out.println("✅ Tenant resolved: " + tenant.getName() + " (ID: " + tenant.getId() + ")");
            } else {
                System.out.println("⚠️ Tenant not found for subdomain: " + subdomain);
                response.sendRedirect("/error?message=Tenant+not+found");
                return false;
            }
        } else {
            System.out.println("ℹ️ No subdomain - accessing main domain");
        }

        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) {
        // Clear tenant context after request completes
        TenantContext.clear();
    }

    /**
     * Extract subdomain from host
     * Examples:
     *   "acme.localhost" -> "acme"
     *   "localhost" -> null
     *   "acme.yourdomain.com" -> "acme"
     *   "yourdomain.com" -> null
     */
    private String extractSubdomain(String host) {
        if (host == null) return null;

        // Remove port if present
        if (host.contains(":")) {
            host = host.substring(0, host.indexOf(":"));
        }

        // Split by dots
        String[] parts = host.split("\\.");

        // For localhost: "acme.localhost" -> parts = ["acme", "localhost"]
        if (parts.length >= 2 && "localhost".equals(parts[parts.length - 1])) {
            return parts[0];
        }

        // For production: "acme.yourdomain.com" -> parts = ["acme", "yourdomain", "com"]
        if (parts.length >= 3) {
            return parts[0];
        }

        // No subdomain found
        return null;
    }
}