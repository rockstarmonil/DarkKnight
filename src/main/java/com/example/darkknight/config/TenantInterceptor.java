package com.example.darkknight.config;

import com.example.darkknight.model.Tenant;
import com.example.darkknight.repository.TenantRepository;
import com.example.darkknight.util.TenantContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import java.util.Optional;

@Component
public class TenantInterceptor implements HandlerInterceptor {

    @Autowired
    private TenantRepository tenantRepository;

    @Value("${app.domain:localhost}")
    private String appDomain;

    @Value("${app.environment:development}")
    private String environment;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String host = request.getServerName();
        String subdomain = extractSubdomain(host);
        String requestUri = request.getRequestURI();

        System.out.println("🌐 Request Host: " + host);
        System.out.println("🔍 Extracted Subdomain: " + subdomain);
        System.out.println("📍 Request URI: " + requestUri);

        // ✅ BLOCK tenant registration from subdomains
        if (requestUri.startsWith("/tenant/register") && subdomain != null && !subdomain.isEmpty()) {
            System.out.println("❌ Blocking tenant registration from subdomain: " + subdomain);
            response.sendRedirect("/login?error=tenant_registration_not_allowed_from_subdomain");
            return false;
        }

        // Skip tenant resolution for main admin routes and static resources
        if (shouldSkipTenantResolution(requestUri)) {
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

                // ✅ Set BOTH tenant ID (Long) and subdomain (String)
                TenantContext.setTenantId(tenant.getId());
                TenantContext.setSubdomain(subdomain);

                System.out.println("✅ Tenant resolved: " + tenant.getName() +
                        " (ID: " + tenant.getId() + ", Subdomain: " + subdomain + ")");
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
    public void postHandle(HttpServletRequest request, HttpServletResponse response,
                           Object handler, ModelAndView modelAndView) throws Exception {
        // Don't clear yet - wait for afterCompletion
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response,
                                Object handler, Exception ex) throws Exception {
        // ✅ Clear after the entire request is complete
        TenantContext.clear();
    }

    /**
     * Check if tenant resolution should be skipped for this URI
     */
    private boolean shouldSkipTenantResolution(String requestUri) {
        return requestUri.startsWith("/main-admin") ||
                requestUri.startsWith("/tenant/register") ||
                requestUri.startsWith("/tenant/check-subdomain") ||
                requestUri.startsWith("/css") ||
                requestUri.startsWith("/js") ||
                requestUri.startsWith("/images") ||
                requestUri.startsWith("/static") ||
                requestUri.startsWith("/favicon.ico") ||
                requestUri.startsWith("/error");
    }

    /**
     * Extract subdomain from host
     */
    private String extractSubdomain(String host) {
        if (host == null || host.isEmpty()) {
            return null;
        }

        // Remove port if present
        if (host.contains(":")) {
            host = host.substring(0, host.indexOf(":"));
        }

        // Convert to lowercase
        host = host.toLowerCase();

        // Check if it's just the base domain
        if (host.equals(appDomain)) {
            return null;
        }

        // Split by dots
        String[] parts = host.split("\\.");

        // Development mode (localhost)
        if ("development".equalsIgnoreCase(environment) || appDomain.equals("localhost")) {
            if (parts.length >= 2 && "localhost".equals(parts[parts.length - 1])) {
                return parts[0];
            }
            if (parts.length == 1 && "localhost".equals(parts[0])) {
                return null;
            }
        }

        // Production mode
        String[] domainParts = appDomain.split("\\.");
        int domainPartCount = domainParts.length;

        if (parts.length > domainPartCount) {
            boolean baseMatches = true;
            for (int i = 0; i < domainPartCount; i++) {
                if (!parts[parts.length - domainPartCount + i].equals(domainParts[i])) {
                    baseMatches = false;
                    break;
                }
            }

            if (baseMatches) {
                return parts[0];
            }
        }

        return null;
    }
}