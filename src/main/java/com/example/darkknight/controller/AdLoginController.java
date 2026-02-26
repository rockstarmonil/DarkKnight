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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.*;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Hashtable;

/**
 * Handles end-user Active Directory login from the login page modal.
 * Mapped at /ad/login so it is publicly accessible (not under /admin/**).
 */
@Controller
@RequestMapping("/ad")
public class AdLoginController {

    @Autowired
    private TenantSsoConfigService ssoConfigService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private SecurityContextRepository securityContextRepository;

    @PostMapping("/login")
    public String loginWithAd(
            @RequestParam("adUsername") String username,
            @RequestParam("adPassword") String password,
            HttpServletRequest request,
            HttpServletResponse response) {

        System.out.println("========================================");
        System.out.println("🔐 AD Login Initiated");
        System.out.println("========================================");

        // ── Resolve tenant ────────────────────────────────────────────────────
        Long tenantIdMut = TenantContext.getTenantId();
        if (tenantIdMut == null) {
            HttpSession sess = request.getSession(false);
            if (sess != null)
                tenantIdMut = (Long) sess.getAttribute("tenantId");
        }
        if (tenantIdMut == null) {
            System.err.println("❌ No tenant context");
            return "redirect:/login?error=no_tenant_context";
        }
        final Long tenantId = tenantIdMut;

        System.out.println("📍 Tenant ID: " + tenantId);
        System.out.println("👤 Username: " + username);

        try {
            // ── Load AD config ────────────────────────────────────────────────
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

            // ── Build bind DN ─────────────────────────────────────────────────
            String bindDn;
            if (username.contains("@") || username.contains("\\")) {
                bindDn = username; // already fully-qualified
            } else if (domain != null && !domain.isBlank()) {
                bindDn = username + "@" + domain; // UPN format
            } else {
                bindDn = username;
            }

            System.out.println("🔗 AD Server: " + serverUrl);
            System.out.println("🔗 Bind DN: " + bindDn);

            // ── LDAP authentication ───────────────────────────────────────────
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, serverUrl);
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, bindDn);
            env.put(Context.SECURITY_CREDENTIALS, password);
            env.put("com.sun.jndi.ldap.connect.timeout", "8000");
            env.put("com.sun.jndi.ldap.read.timeout", "8000");

            DirContext ctx = null;
            String email = null;
            String firstName = "AD";
            String lastName = "User";

            try {
                ctx = new InitialDirContext(env);
                System.out.println("✅ LDAP bind successful for: " + bindDn);

                // Try to fetch mail, givenName, sn attributes
                if (baseDn != null && !baseDn.isBlank()) {
                    try {
                        String filter = "(|(sAMAccountName=" + escapeLdap(username)
                                + ")(userPrincipalName=" + escapeLdap(bindDn) + "))";
                        SearchControls sc = new SearchControls();
                        sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
                        sc.setReturningAttributes(new String[] { "mail", "userPrincipalName", "givenName", "sn" });
                        sc.setCountLimit(1);

                        NamingEnumeration<SearchResult> results = ctx.search(baseDn, filter, sc);
                        if (results.hasMore()) {
                            Attributes attrs = results.next().getAttributes();
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
                return "redirect:/login?error="
                        + URLEncoder.encode("Invalid Active Directory credentials", StandardCharsets.UTF_8);
            } catch (javax.naming.CommunicationException ce) {
                System.err.println("❌ Cannot reach AD server: " + ce.getMessage());
                return "redirect:/login?error="
                        + URLEncoder.encode("Cannot reach Active Directory server", StandardCharsets.UTF_8);
            } finally {
                if (ctx != null) {
                    try {
                        ctx.close();
                    } catch (Exception ignored) {
                    }
                }
            }

            // Fall back to a derived email if attribute not found
            if (email == null || email.isBlank()) {
                email = username.contains("@") ? username
                        : username + "@" + (domain != null ? domain : "ad.local");
                System.out.println("⚠️ Using derived email: " + email);
            }

            // ── Find or create local user record ──────────────────────────────
            final String fEmail = email;
            final String fFirst = firstName;
            final String fLast = lastName;

            com.example.darkknight.model.Tenant tenant = tenantRepository.findById(tenantId)
                    .orElseThrow(() -> new RuntimeException("Tenant not found: " + tenantId));

            com.example.darkknight.model.User user = userRepository.findByEmailAndTenantId(fEmail, tenantId)
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
                        u.setCreatedAt(LocalDateTime.now());
                        u.setUpdatedAt(LocalDateTime.now());
                        return u;
                    });

            user.setUpdatedAt(LocalDateTime.now());
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

            // ── Role-based redirect ───────────────────────────────────────────
            String dest = "ROLE_ADMIN".equalsIgnoreCase(user.getRole())
                    ? "/tenant-admin/dashboard"
                    : "/user/dashboard";
            System.out.println("🔀 Redirecting to: " + dest);
            System.out.println("========================================");
            return "redirect:" + dest;

        } catch (Exception e) {
            System.err.println("❌ AD Login error: " + e.getMessage());
            e.printStackTrace();
            return "redirect:/login?error="
                    + URLEncoder.encode("AD authentication failed: " + e.getMessage(), StandardCharsets.UTF_8);
        }
    }

    // ── LDAP helpers ──────────────────────────────────────────────────────────

    private String getAttr(Attributes attrs, String name) {
        Attribute a = attrs.get(name);
        if (a == null)
            return null;
        try {
            return (String) a.get();
        } catch (Exception e) {
            return null;
        }
    }

    private String nvl(String v, String fallback) {
        return (v != null && !v.isBlank()) ? v : fallback;
    }

    private String escapeLdap(String s) {
        return s.replace("\\", "\\5c").replace("*", "\\2a")
                .replace("(", "\\28").replace(")", "\\29").replace("\0", "\\00");
    }
}
