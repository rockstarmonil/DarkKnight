package com.example.darkknight.config;

import com.example.darkknight.model.Tenant;
import com.example.darkknight.repository.TenantRepository;
import com.example.darkknight.util.TenantContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
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

        // ✅ SPECIAL HANDLING FOR OAuth/SAML/JWT CALLBACKS
        if (isAuthCallbackEndpoint(requestUri)) {
            System.out.println("🔄 Auth callback detected - restoring tenant context");
            
            // Try to restore tenant context from session
            HttpSession session = request.getSession(false);
            if (session != null) {
                Long savedTenantId = (Long) session.getAttribute("oauth_tenant_id");
                String savedSubdomain = (String) session.getAttribute("oauth_subdomain");
                
                if (savedTenantId != null) {
                    TenantContext.setTenantId(savedTenantId);
                    if (savedSubdomain != null) {
                        TenantContext.setSubdomain(savedSubdomain);
                    }
                    System.out.println("✅ Restored tenant context from session - ID: " + savedTenantId + ", Subdomain: " + savedSubdomain);
                    return true;
                }
            }
            
            // If no session data, try to extract from subdomain
            if (subdomain != null && !subdomain.isEmpty()) {
                Optional<Tenant> tenantOpt = tenantRepository.findBySubdomain(subdomain);
                if (tenantOpt.isPresent()) {
                    Tenant tenant = tenantOpt.get();
                    TenantContext.setTenantId(tenant.getId());
                    TenantContext.setSubdomain(subdomain);
                    System.out.println("✅ Tenant resolved from subdomain for callback: " + tenant.getName());
                    return true;
                }
            }
            
            System.err.println("⚠️ Could not restore tenant context for auth callback");
            return true;
        }

        // ✅ SPECIAL HANDLING FOR AUTHENTICATED USER PAGES
        if (isAuthenticatedUserEndpoint(requestUri)) {
            System.out.println("🔒 Authenticated endpoint detected - checking tenant context");
            
            // First, try to get from current context
            Long tenantId = TenantContext.getTenantId();
            
            // If not in context, try to restore from session
            if (tenantId == null) {
                HttpSession session = request.getSession(false);
                if (session != null) {
                    tenantId = (Long) session.getAttribute("oauth_tenant_id");
                    String savedSubdomain = (String) session.getAttribute("oauth_subdomain");
                    
                    if (tenantId != null) {
                        TenantContext.setTenantId(tenantId);
                        if (savedSubdomain != null) {
                            TenantContext.setSubdomain(savedSubdomain);
                        }
                        System.out.println("✅ Restored tenant context for authenticated page from session");
                    }
                }
            }
            
            // If still no tenant, try from subdomain
            if (tenantId == null && subdomain != null && !subdomain.isEmpty()) {
                Optional<Tenant> tenantOpt = tenantRepository.findBySubdomain(subdomain);
                if (tenantOpt.isPresent()) {
                    Tenant tenant = tenantOpt.get();
                    TenantContext.setTenantId(tenant.getId());
                    TenantContext.setSubdomain(subdomain);
                    System.out.println("✅ Tenant resolved from subdomain: " + tenant.getName());
                }
            }
            
            return true;
        }

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
        String requestUri = request.getRequestURI();
        
        // ✅ DON'T clear tenant context for auth callbacks or authenticated pages
        // Let them maintain context across redirects
        if (!isAuthCallbackEndpoint(requestUri) && !isAuthenticatedUserEndpoint(requestUri)) {
            TenantContext.clear();
            System.out.println("🧹 Cleared tenant context for: " + requestUri);
        } else {
            System.out.println("⚠️ Keeping tenant context alive for: " + requestUri);
        }
    }

    /**
     * Check if this is an OAuth/SAML/JWT callback endpoint
     */
    private boolean isAuthCallbackEndpoint(String requestUri) {
        return requestUri.startsWith("/oauth/callback") ||
                requestUri.startsWith("/sso/saml/callback") ||
                requestUri.startsWith("/jwt/callback");
    }

    /**
     * Check if this is an authenticated user endpoint (dashboard, etc.)
     */
    private boolean isAuthenticatedUserEndpoint(String requestUri) {
        return requestUri.startsWith("/user/dashboard") ||
                requestUri.startsWith("/tenant-admin/dashboard") ||
                requestUri.startsWith("/user/") ||
                requestUri.startsWith("/tenant-admin/");
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