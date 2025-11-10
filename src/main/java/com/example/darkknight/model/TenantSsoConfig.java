package com.example.darkknight.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "tenant_sso_config")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class TenantSsoConfig {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne
    @JoinColumn(name = "tenant_id", unique = true, nullable = false)
    private Tenant tenant;

    // ===============================
    // SAML Configuration
    // ===============================
    @Column(name = "saml_enabled")
    private Boolean samlEnabled = false;

    @Column(name = "saml_idp_login_url", length = 500)
    private String samlIdpLoginUrl;

    @Column(name = "saml_sp_entity_id", length = 500)
    private String samlSpEntityId;

    @Column(name = "saml_sp_acs_url", length = 500)
    private String samlSpAcsUrl;

    @Column(name = "saml_sp_binding", length = 200)
    private String samlSpBinding;

    @Column(name = "saml_sp_nameid_format", length = 200)
    private String samlSpNameIdFormat;

    @Column(name = "saml_certificate_path", length = 500)
    private String samlCertificatePath;

    // ===============================
    // OAuth/OIDC Configuration
    // ===============================
    @Column(name = "oauth_enabled")
    private Boolean oauthEnabled = false;

    @Column(name = "oauth_client_id", length = 500)
    private String oauthClientId;

    @Column(name = "oauth_client_secret", length = 500)
    private String oauthClientSecret;

    @Column(name = "oauth_redirect_uri", length = 500)
    private String oauthRedirectUri;

    @Column(name = "oauth_authorization_url", length = 500)
    private String oauthAuthorizationUrl;

    @Column(name = "oauth_token_url", length = 500)
    private String oauthTokenUrl;

    @Column(name = "oauth_userinfo_url", length = 500)
    private String oauthUserinfoUrl;

    // ===============================
    // JWT Configuration (MiniOrange)
    // ===============================
    @Column(name = "jwt_enabled")
    private Boolean jwtEnabled = false;

    @Column(name = "miniorange_login_url", length = 500)
    private String miniorangeLoginUrl;

    @Column(name = "miniorange_client_id", length = 500)
    private String miniorangeClientId;

    @Column(name = "miniorange_client_secret", length = 500)
    private String miniorangeClientSecret;

    @Column(name = "miniorange_redirect_uri", length = 500)
    private String miniorangeRedirectUri;

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
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    /**
     * Check if any SSO method is enabled
     */
    public boolean isAnySsoEnabled() {
        return Boolean.TRUE.equals(samlEnabled) ||
                Boolean.TRUE.equals(oauthEnabled) ||
                Boolean.TRUE.equals(jwtEnabled);
    }

    /**
     * Get enabled SSO methods as a comma-separated string
     */
    public String getEnabledSsoMethods() {
        StringBuilder methods = new StringBuilder();
        if (Boolean.TRUE.equals(samlEnabled)) methods.append("SAML,");
        if (Boolean.TRUE.equals(oauthEnabled)) methods.append("OAuth,");
        if (Boolean.TRUE.equals(jwtEnabled)) methods.append("JWT,");

        if (methods.length() > 0) {
            methods.setLength(methods.length() - 1); // Remove trailing comma
        }

        return methods.toString();
    }
}