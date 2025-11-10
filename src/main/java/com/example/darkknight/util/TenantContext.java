package com.example.darkknight.util;

public class TenantContext {
    private static final ThreadLocal<Long> currentTenantId = new ThreadLocal<>();
    private static final ThreadLocal<String> currentSubdomain = new ThreadLocal<>();

    public static void setTenantId(Long tenantId) {
        currentTenantId.set(tenantId);
    }

    public static Long getTenantId() {
        return currentTenantId.get();
    }

    public static void setSubdomain(String subdomain) {
        currentSubdomain.set(subdomain);
    }

    public static String getSubdomain() {
        return currentSubdomain.get();
    }

    public static void clear() {
        currentTenantId.remove();
        currentSubdomain.remove();
    }

    public static boolean hasTenant() {
        return currentTenantId.get() != null;
    }
}