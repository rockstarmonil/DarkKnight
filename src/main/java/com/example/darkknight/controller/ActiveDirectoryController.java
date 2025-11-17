package com.example.darkknight.controller;

import com.example.darkknight.model.TenantSsoConfig;
import com.example.darkknight.service.TenantSsoConfigService;
import com.example.darkknight.util.TenantContext;
import org.springframework.beans.factory.annotation.Autowired;
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

                        NamingEnumeration<SearchResult> results =
                                ctx.search(baseDn, "(objectClass=user)", searchControls);

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
}