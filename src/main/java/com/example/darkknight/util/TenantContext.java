package com.example.darkknight.util;

/**
 * Thread-local storage for current tenant context
 * This allows us to track which tenant is making the current request
 */
public class TenantContext {

    private static final ThreadLocal<Long> currentTenant = new ThreadLocal<>();
    private static final ThreadLocal<String> currentSubdomain = new ThreadLocal<>();

    public static void setTenantId(Long tenantId) {
        currentTenant.set(tenantId);
        System.out.println("🔹 TenantContext: Set tenant ID = " + tenantId);
    }

    public static Long getTenantId() {
        return currentTenant.get();
    }

    public static void setSubdomain(String subdomain) {
        currentSubdomain.set(subdomain);
    }

    public static String getSubdomain() {
        return currentSubdomain.get();
    }

    public static void clear() {
        currentTenant.remove();
        currentSubdomain.remove();
        System.out.println("🔹 TenantContext: Cleared");
    }

    public static boolean hasTenant() {
        return currentTenant.get() != null;
    }
}