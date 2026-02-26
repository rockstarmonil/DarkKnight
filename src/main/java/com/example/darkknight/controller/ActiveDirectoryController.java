package com.example.darkknight.controller;

import com.example.darkknight.model.TenantSsoConfig;
import com.example.darkknight.repository.TenantRepository;
import com.example.darkknight.repository.UserRepository;
import com.example.darkknight.security.CustomUserDetails;
import com.example.darkknight.service.TenantSsoConfigService;
import com.example.darkknight.util.TenantContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.*;
import java.net.Socket;
import java.util.*;

@Controller
@RequestMapping("/admin/ad")
public class ActiveDirectoryController {

    @Autowired
    private TenantSsoConfigService ssoConfigService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private SecurityContextRepository securityContextRepository;

    /**
     * Save Active Directory configuration
     */
    @PostMapping("/save-config")
    @ResponseBody
    public Map<String, Object> saveAdConfig(@RequestBody Map<String, Object> request) {
        Map<String, Object> response = new HashMap<>();

        try {
            Long tenantId = TenantContext.getTenantId();
            if (tenantId == null) {
                response.put("success", false);
                response.put("message", "No tenant context found");
                return response;
            }

            TenantSsoConfig ssoConfig = ssoConfigService.getOrCreateSsoConfig(tenantId);

            // Update AD configuration
            ssoConfig.setAdEnabled((Boolean) request.get("adEnabled"));
            ssoConfig.setAdServerUrl((String) request.get("adServerUrl"));
            ssoConfig.setAdUsername((String) request.get("adUsername"));
            ssoConfig.setAdPassword((String) request.get("adPassword"));
            ssoConfig.setAdBaseDn((String) request.get("adBaseDn"));
            ssoConfig.setAdDomain((String) request.get("adDomain"));

            ssoConfigService.saveSsoConfig(ssoConfig);

            System.out.println("✅ AD configuration saved for tenant: " + tenantId);

            response.put("success", true);
            response.put("message", "Active Directory configuration saved successfully");

        } catch (Exception e) {
            System.err.println("❌ Error saving AD config: " + e.getMessage());
            e.printStackTrace();
            response.put("success", false);
            response.put("message", "Failed to save configuration: " + e.getMessage());
        }

        return response;
    }

    /**
     * Test Active Directory connection (ping test)
     */
    @PostMapping("/test-connection")
    @ResponseBody
    public Map<String, Object> testConnection(@RequestBody Map<String, String> request) {
        Map<String, Object> response = new HashMap<>();

        try {
            String serverUrl = request.get("serverUrl");

            if (serverUrl == null || serverUrl.isEmpty()) {
                response.put("success", false);
                response.put("message", "Server URL is required");
                return response;
            }

            System.out.println("🧪 Testing AD connection to: " + serverUrl);

            // Parse server URL to get host and port
            String host;
            int port;

            if (serverUrl.startsWith("ldap://")) {
                serverUrl = serverUrl.substring(7);
                port = 389; // Default LDAP port
            } else if (serverUrl.startsWith("ldaps://")) {
                serverUrl = serverUrl.substring(8);
                port = 636; // Default LDAPS port
            } else {
                port = 389; // Default
            }

            // Extract host and port
            if (serverUrl.contains(":")) {
                String[] parts = serverUrl.split(":");
                host = parts[0];
                port = Integer.parseInt(parts[1]);
            } else {
                host = serverUrl;
            }

            System.out.println("🔍 Connecting to " + host + ":" + port);

            // Test connection with socket
            try (Socket socket = new Socket()) {
                socket.connect(new java.net.InetSocketAddress(host, port), 5000);

                System.out.println("✅ AD server is reachable");

                response.put("success", true);
                response.put("message", "Successfully connected to " + host + ":" + port);
                response.put("host", host);
                response.put("port", port);

            } catch (Exception e) {
                System.err.println("❌ Connection failed: " + e.getMessage());
                response.put("success", false);
                response.put("message", "Cannot reach server " + host + ":" + port + " - " + e.getMessage());
            }

        } catch (Exception e) {
            System.err.println("❌ Test connection error: " + e.getMessage());
            e.printStackTrace();
            response.put("success", false);
            response.put("message", "Connection test failed: " + e.getMessage());
        }

        return response;
    }

    /**
     * Test Active Directory authentication
     */
    @PostMapping("/test-auth")
    @ResponseBody
    public Map<String, Object> testAuthentication(@RequestBody Map<String, String> request) {
        Map<String, Object> response = new HashMap<>();

        try {
            String serverUrl = request.get("serverUrl");
            String username = request.get("username");
            String password = request.get("password");
            String baseDn = request.get("baseDn");

            if (serverUrl == null || username == null || password == null) {
                response.put("success", false);
                response.put("message", "Server URL, username, and password are required");
                return response;
            }

            System.out.println("🧪 Testing AD authentication");
            System.out.println("   Server: " + serverUrl);
            System.out.println("   Username: " + username);
            System.out.println("   Base DN: " + baseDn);

            // Set up LDAP environment
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, serverUrl);
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, username);
            env.put(Context.SECURITY_CREDENTIALS, password);

            // Set timeout
            env.put("com.sun.jndi.ldap.connect.timeout", "5000");
            env.put("com.sun.jndi.ldap.read.timeout", "5000");

            // Try to connect and authenticate
            DirContext ctx = null;
            try {
                ctx = new InitialDirContext(env);

                System.out.println("✅ AD authentication successful");

                // Try to count users if baseDn is provided
                int userCount = 0;
                if (baseDn != null && !baseDn.isEmpty()) {
                    try {
                        SearchControls searchControls = new SearchControls();
                        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
                        searchControls.setCountLimit(100); // Limit to first 100 users

                        NamingEnumeration<SearchResult> results = ctx.search(baseDn, "(objectClass=user)",
                                searchControls);

                        while (results.hasMore()) {
                            results.next();
                            userCount++;
                        }

                        System.out.println("📊 Found " + userCount + " users in directory");
                    } catch (Exception e) {
                        System.out.println("⚠️ Could not count users: " + e.getMessage());
                    }
                }

                response.put("success", true);
                response.put("message", "Authentication successful! Connected to Active Directory");
                response.put("userCount", userCount);

            } catch (javax.naming.AuthenticationException e) {
                System.err.println("❌ Authentication failed: Invalid credentials");
                response.put("success", false);
                response.put("message", "Authentication failed: Invalid username or password");
            } catch (javax.naming.CommunicationException e) {
                System.err.println("❌ Communication error: " + e.getMessage());
                response.put("success", false);
                response.put("message", "Cannot communicate with AD server: " + e.getMessage());
            } catch (Exception e) {
                System.err.println("❌ LDAP error: " + e.getMessage());
                response.put("success", false);
                response.put("message", "LDAP error: " + e.getMessage());
            } finally {
                if (ctx != null) {
                    try {
                        ctx.close();
                    } catch (Exception e) {
                        // Ignore
                    }
                }
            }

        } catch (Exception e) {
            System.err.println("❌ Test authentication error: " + e.getMessage());
            e.printStackTrace();
            response.put("success", false);
            response.put("message", "Authentication test failed: " + e.getMessage());
        }

        return response;
    }

    // ====================================================================
    // AD LOGIN — called from the login page modal
    // ====================================================================

    /**
     * Authenticate an end-user against the tenant's Active Directory / LDAP server.
     * The request comes from the AD login modal on the login page (POST form).
     * On success the user is redirected to the appropriate dashboard;
     * on failure they are sent back to login with an error.
     */
    @PostMapping("/login")
    public String loginWithAd(
            @RequestParam("adUsername") String username,
            @RequestParam("adPassword") String password,
            HttpServletRequest request,
            HttpServletResponse response) {

        System.out.println("========================================");
        System.out.println("🔐 AD Login Initiated");
        System.out.println("========================================");

        Long tenantIdMut = TenantContext.getTenantId();

        // Fallback to session if TenantContext is empty (cross-request)
        if (tenantIdMut == null) {
            HttpSession sess = request.getSession(false);
            if (sess != null)
                tenantIdMut = (Long) sess.getAttribute("tenantId");
        }

        if (tenantIdMut == null) {
            System.err.println("❌ No tenant context");
            return "redirect:/login?error=no_tenant_context";
        }

        final Long tenantId = tenantIdMut; // effectively final for use in lambdas

        System.out.println("📍 Tenant ID: " + tenantId);
        System.out.println("👤 Username: " + username);

        try {
            // ── Load AD config ──────────────────────────────────────────────
            TenantSsoConfig cfg = ssoConfigService.getOrCreateSsoConfig(tenantId);

            if (!Boolean.TRUE.equals(cfg.getAdEnabled())) {
                System.err.println("❌ AD not enabled for tenant: " + tenantId);
                return "redirect:/login?error=ad_not_enabled";
            }

            String serverUrl = cfg.getAdServerUrl();
            String baseDn = cfg.getAdBaseDn();
            String domain = cfg.getAdDomain();

            if (serverUrl == null || serverUrl.isBlank()) {
                System.err.println("❌ AD server URL not configured");
                return "redirect:/login?error=ad_not_configured";
            }

            // ── Build bind DN ────────────────────────────────────────────────
            // Support full UPN (user@domain), sAMAccountName with domain prefix, or plain
            // username
            String bindDn;
            if (username.contains("@") || username.contains("\\")) {
                bindDn = username;
            } else if (domain != null && !domain.isBlank()) {
                bindDn = username + "@" + domain;
            } else {
                bindDn = username;
            }

            System.out.println("🔗 AD Server: " + serverUrl);
            System.out.println("🔗 Bind DN: " + bindDn);

            // ── LDAP authentication ──────────────────────────────────────────
            java.util.Hashtable<String, String> env = new java.util.Hashtable<>();
            env.put(javax.naming.Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(javax.naming.Context.PROVIDER_URL, serverUrl);
            env.put(javax.naming.Context.SECURITY_AUTHENTICATION, "simple");
            env.put(javax.naming.Context.SECURITY_PRINCIPAL, bindDn);
            env.put(javax.naming.Context.SECURITY_CREDENTIALS, password);
            env.put("com.sun.jndi.ldap.connect.timeout", "8000");
            env.put("com.sun.jndi.ldap.read.timeout", "8000");

            javax.naming.directory.DirContext ctx = null;
            String email = null;
            String firstName = "AD";
            String lastName = "User";

            try {
                ctx = new javax.naming.directory.InitialDirContext(env);
                System.out.println("✅ LDAP bind successful for: " + bindDn);

                // Try to fetch mail, givenName, sn attributes
                if (baseDn != null && !baseDn.isBlank()) {
                    try {
                        String filter = "(|(sAMAccountName=" + escapeLdap(username)
                                + ")(userPrincipalName=" + escapeLdap(bindDn) + "))";
                        javax.naming.directory.SearchControls sc = new javax.naming.directory.SearchControls();
                        sc.setSearchScope(javax.naming.directory.SearchControls.SUBTREE_SCOPE);
                        sc.setReturningAttributes(new String[] { "mail", "userPrincipalName", "givenName", "sn" });
                        sc.setCountLimit(1);

                        javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results = ctx.search(baseDn,
                                filter, sc);

                        if (results.hasMore()) {
                            javax.naming.directory.Attributes attrs = results.next().getAttributes();
                            email = getAttr(attrs, "mail");
                            if (email == null)
                                email = getAttr(attrs, "userPrincipalName");
                            firstName = nvl(getAttr(attrs, "givenName"), firstName);
                            lastName = nvl(getAttr(attrs, "sn"), lastName);
                        }
                    } catch (Exception ex) {
                        System.out.println("⚠️ Could not fetch LDAP attributes: " + ex.getMessage());
                    }
                }

            } catch (javax.naming.AuthenticationException ae) {
                System.err.println("❌ Invalid AD credentials for: " + bindDn);
                return "redirect:/login?error=Invalid+Active+Directory+credentials";
            } catch (javax.naming.CommunicationException ce) {
                System.err.println("❌ Cannot reach AD server: " + ce.getMessage());
                return "redirect:/login?error=Cannot+reach+Active+Directory+server";
            } finally {
                if (ctx != null) {
                    try {
                        ctx.close();
                    } catch (Exception ignored) {
                    }
                }
            }

            // Fall back: derive email from username
            if (email == null || email.isBlank()) {
                email = username.contains("@") ? username
                        : username + "@" + (domain != null ? domain : "ad.local");
                System.out.println("⚠️ Using derived email: " + email);
            }

            // ── Find or create local user record ─────────────────────────────
            final Long fTenantId = tenantId;
            final String fEmail = email;
            final String fFirst = firstName;
            final String fLast = lastName;

            com.example.darkknight.model.Tenant tenant = tenantRepository.findById(tenantId)
                    .orElseThrow(() -> new RuntimeException("Tenant not found: " + tenantId));

            com.example.darkknight.model.User user = userRepository.findByEmailAndTenantId(fEmail, fTenantId)
                    .orElseGet(() -> {
                        System.out.println("➕ Creating new AD user: " + fEmail);
                        com.example.darkknight.model.User u = new com.example.darkknight.model.User();
                        u.setEmail(fEmail);
                        u.setUsername(fEmail);
                        u.setFirstName(fFirst);
                        u.setLastName(fLast);
                        u.setRole("ROLE_USER");
                        u.setEnabled(true);
                        u.setTenant(tenant);
                        u.setPassword("");
                        u.setCreatedAt(java.time.LocalDateTime.now());
                        u.setUpdatedAt(java.time.LocalDateTime.now());
                        return u;
                    });

            user.setUpdatedAt(java.time.LocalDateTime.now());
            userRepository.save(user);
            System.out.println("💾 AD user saved — ID: " + user.getId() + ", role: " + user.getRole());

            // ── Build Spring Security context ─────────────────────────────────
            CustomUserDetails ud = new CustomUserDetails(user);
            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(ud, null,
                    ud.getAuthorities());

            SecurityContextHolder.getContext().setAuthentication(auth);
            securityContextRepository.saveContext(SecurityContextHolder.getContext(), request, response);

            HttpSession session = request.getSession(true);
            session.setAttribute("user", user);
            session.setAttribute("isLoggedIn", true);
            session.setAttribute("adAuthenticated", true);
            session.setAttribute("tenantId", tenantId);

            System.out.println("✅ AD Login Successful — " + user.getEmail());

            // ── Role-based redirect ────────────────────────────────────────────
            String dest = "ROLE_ADMIN".equalsIgnoreCase(user.getRole())
                    ? "/tenant-admin/dashboard"
                    : "/user/dashboard";
            System.out.println("🔀 Redirecting to: " + dest);
            System.out.println("========================================");
            return "redirect:" + dest;

        } catch (Exception e) {
            System.err.println("❌ AD Login error: " + e.getMessage());
            e.printStackTrace();
            return "redirect:/login?error=AD+authentication+failed";
        }
    }

    // ── LDAP helpers ──────────────────────────────────────────────────────────

    /** Return attribute value or null. */
    private String getAttr(javax.naming.directory.Attributes attrs, String name) {
        javax.naming.directory.Attribute a = attrs.get(name);
        if (a == null)
            return null;
        try {
            return (String) a.get();
        } catch (Exception e) {
            return null;
        }
    }

    /** Return v when non-null/non-blank, else fallback. */
    private String nvl(String v, String fallback) {
        return (v != null && !v.isBlank()) ? v : fallback;
    }

    /** Escape special characters for LDAP search filter (RFC 4515). */
    private String escapeLdap(String s) {
        return s.replace("\\", "\\5c").replace("*", "\\2a")
                .replace("(", "\\28").replace(")", "\\29").replace("\0", "\\00");
    }
}