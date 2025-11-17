package com.example.darkknight.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "active_directory_config")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ActiveDirectoryConfig {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne
    @JoinColumn(name = "tenant_id", unique = true, nullable = false)
    private Tenant tenant;

    // ===============================
    // AD Connection Configuration
    // ===============================
    @Column(name = "enabled")
    private Boolean enabled = false;

    @Column(name = "server_url", length = 500)
    private String serverUrl;

    @Column(name = "port")
    private Integer port;

    @Column(name = "use_ssl")
    private Boolean useSsl = false;

    // ===============================
    // Authentication Configuration
    // ===============================
    @Column(name = "bind_username", length = 500)
    private String bindUsername;

    @Column(name = "bind_password", length = 500)
    private String bindPassword;

    @Column(name = "base_dn", length = 500)
    private String baseDn;

    @Column(name = "domain", length = 255)
    private String domain;

    // ===============================
    // Search Configuration
    // ===============================
    @Column(name = "user_search_filter", length = 255)
    private String userSearchFilter;

    @Column(name = "user_search_base", length = 500)
    private String userSearchBase;

    @Column(name = "group_search_filter", length = 255)
    private String groupSearchFilter;

    @Column(name = "group_search_base", length = 500)
    private String groupSearchBase;

    // ===============================
    // Attribute Mapping
    // ===============================
    @Column(name = "email_attribute", length = 100)
    private String emailAttribute;

    @Column(name = "first_name_attribute", length = 100)
    private String firstNameAttribute;

    @Column(name = "last_name_attribute", length = 100)
    private String lastNameAttribute;

    @Column(name = "username_attribute", length = 100)
    private String usernameAttribute;

    // ===============================
    // Connection Settings
    // ===============================
    @Column(name = "connection_timeout")
    private Integer connectionTimeout;

    @Column(name = "read_timeout")
    private Integer readTimeout;

    // ===============================
    // Status & Testing
    // ===============================
    @Column(name = "last_test_status")
    private String lastTestStatus;

    @Column(name = "last_test_time")
    private LocalDateTime lastTestTime;

    @Column(name = "last_test_message", length = 1000)
    private String lastTestMessage;

    // ===============================
    // Metadata
    // ===============================
    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();

        // Set default values
        if (port == null) {
            port = useSsl ? 636 : 389;
        }
        if (connectionTimeout == null) {
            connectionTimeout = 5000; // 5 seconds
        }
        if (readTimeout == null) {
            readTimeout = 5000; // 5 seconds
        }
        if (emailAttribute == null) {
            emailAttribute = "mail";
        }
        if (firstNameAttribute == null) {
            firstNameAttribute = "givenName";
        }
        if (lastNameAttribute == null) {
            lastNameAttribute = "sn";
        }
        if (usernameAttribute == null) {
            usernameAttribute = "sAMAccountName";
        }
        if (userSearchFilter == null) {
            userSearchFilter = "(objectClass=user)";
        }
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    /**
     * Get full LDAP URL
     */
    public String getFullLdapUrl() {
        if (serverUrl == null) {
            return null;
        }

        String protocol = Boolean.TRUE.equals(useSsl) ? "ldaps://" : "ldap://";
        String url = serverUrl;

        // Remove protocol if already present
        if (url.startsWith("ldap://") || url.startsWith("ldaps://")) {
            url = url.replaceFirst("^ldaps?://", "");
        }

        // Add port if not present in URL
        if (!url.contains(":")) {
            url += ":" + (port != null ? port : (Boolean.TRUE.equals(useSsl) ? 636 : 389));
        }

        return protocol + url;
    }

    /**
     * Update test status
     */
    public void updateTestStatus(boolean success, String message) {
        this.lastTestStatus = success ? "SUCCESS" : "FAILED";
        this.lastTestTime = LocalDateTime.now();
        this.lastTestMessage = message;
    }
}