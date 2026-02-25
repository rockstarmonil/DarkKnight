package com.example.darkknight.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.validation.constraints.Size;
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

    @Size(max = 500, message = "SAML IDP Login URL must not exceed 500 characters")
    @Column(name = "saml_idp_login_url", length = 500)
    private String samlIdpLoginUrl;

    @Size(max = 500, message = "SAML SP Entity ID must not exceed 500 characters")
    @Column(name = "saml_sp_entity_id", length = 500)
    private String samlSpEntityId;

    @Size(max = 500, message = "SAML SP ACS URL must not exceed 500 characters")
    @Column(name = "saml_sp_acs_url", length = 500)
    private String samlSpAcsUrl;

    @Size(max = 200, message = "SAML SP Binding must not exceed 200 characters")
    @Column(name = "saml_sp_binding", length = 200)
    private String samlSpBinding;

    @Size(max = 200, message = "SAML SP NameID Format must not exceed 200 characters")
    @Column(name = "saml_sp_nameid_format", length = 200)
    private String samlSpNameIdFormat;

    @Size(max = 500, message = "SAML Certificate Path must not exceed 500 characters")
    @Column(name = "saml_certificate_path", length = 500)
    private String samlCertificatePath; // kept for backward compatibility

    @Size(max = 500, message = "SAML IdP Entity ID must not exceed 500 characters")
    @Column(name = "saml_idp_entity_id", length = 500)
    private String samlIdpEntityId;

    // Stores the raw X.509 PEM certificate pasted by the admin
    @Column(name = "saml_idp_certificate", columnDefinition = "TEXT")
    private String samlIdpCertificate;

    // ===============================
    // OAuth/OIDC Configuration
    // ===============================
    @Column(name = "oauth_enabled")
    private Boolean oauthEnabled = false;

    @Size(max = 500, message = "OAuth Client ID must not exceed 500 characters")
    @Column(name = "oauth_client_id", length = 500)
    private String oauthClientId;

    @JsonIgnore // Prevent serialization in JSON responses
    @Size(max = 500, message = "OAuth Client Secret must not exceed 500 characters")
    @Column(name = "oauth_client_secret", length = 500)
    private String oauthClientSecret;

    @Size(max = 500, message = "OAuth Redirect URI must not exceed 500 characters")
    @Column(name = "oauth_redirect_uri", length = 500)
    private String oauthRedirectUri;

    @Size(max = 500, message = "OAuth Authorization URL must not exceed 500 characters")
    @Column(name = "oauth_authorization_url", length = 500)
    private String oauthAuthorizationUrl;

    @Size(max = 500, message = "OAuth Token URL must not exceed 500 characters")
    @Column(name = "oauth_token_url", length = 500)
    private String oauthTokenUrl;

    @Size(max = 500, message = "OAuth Userinfo URL must not exceed 500 characters")
    @Column(name = "oauth_userinfo_url", length = 500)
    private String oauthUserinfoUrl;

    // ===============================
    // JWT Configuration (MiniOrange)
    // ===============================
    @Column(name = "jwt_enabled")
    private Boolean jwtEnabled = false;

    @Size(max = 500, message = "MiniOrange Login URL must not exceed 500 characters")
    @Column(name = "miniorange_login_url", length = 500)
    private String miniorangeLoginUrl;

    @Size(max = 500, message = "MiniOrange Client ID must not exceed 500 characters")
    @Column(name = "miniorange_client_id", length = 500)
    private String miniorangeClientId;

    @JsonIgnore // Prevent serialization in JSON responses
    @Size(max = 500, message = "MiniOrange Client Secret must not exceed 500 characters")
    @Column(name = "miniorange_client_secret", length = 500)
    private String miniorangeClientSecret;

    @Size(max = 500, message = "MiniOrange Redirect URI must not exceed 500 characters")
    @Column(name = "miniorange_redirect_uri", length = 500)
    private String miniorangeRedirectUri;

    /**
     * HMAC signing algorithm used to validate the JWT token issued by the IdP.
     * Supported values: "HS256" (default), "HS384", "HS512".
     * Displayed in the UI so administrators know which algorithm to configure
     * on their IdP side.
     */
    @Size(max = 10, message = "JWT Algorithm must not exceed 10 characters")
    @Column(name = "jwt_algorithm", length = 10)
    private String jwtAlgorithm = "HS256";

    // ===============================
    // Active Directory Configuration
    // ===============================
    @Column(name = "ad_enabled")
    private Boolean adEnabled = false;

    @Size(max = 500, message = "AD Server URL must not exceed 500 characters")
    @Column(name = "ad_server_url", length = 500)
    private String adServerUrl;

    @Size(max = 500, message = "AD Username must not exceed 500 characters")
    @Column(name = "ad_username", length = 500)
    private String adUsername;

    @JsonIgnore // Prevent serialization in JSON responses
    @Size(max = 500, message = "AD Password must not exceed 500 characters")
    @Column(name = "ad_password", length = 500)
    private String adPassword;

    @Size(max = 500, message = "AD Base DN must not exceed 500 characters")
    @Column(name = "ad_base_dn", length = 500)
    private String adBaseDn;

    @Size(max = 255, message = "AD Domain must not exceed 255 characters")
    @Column(name = "ad_domain", length = 255)
    private String adDomain;

    // ===============================
    // Metadata
    // ===============================
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        createdAt = now;
        updatedAt = now;
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
                Boolean.TRUE.equals(jwtEnabled) ||
                Boolean.TRUE.equals(adEnabled);
    }

    /**
     * Get enabled SSO methods as a comma-separated string
     */
    public String getEnabledSsoMethods() {
        StringBuilder methods = new StringBuilder();
        if (Boolean.TRUE.equals(samlEnabled))
            methods.append("SAML,");
        if (Boolean.TRUE.equals(oauthEnabled))
            methods.append("OAuth,");
        if (Boolean.TRUE.equals(jwtEnabled))
            methods.append("JWT,");
        if (Boolean.TRUE.equals(adEnabled))
            methods.append("Active Directory,");

        if (methods.length() > 0) {
            methods.setLength(methods.length() - 1); // Remove trailing comma
        }

        return methods.toString();
    }

    /**
     * Check if secrets should be encrypted
     * Note: In production, implement proper encryption for secrets
     */
    @JsonIgnore
    public boolean hasSecrets() {
        return (oauthClientSecret != null && !oauthClientSecret.isEmpty()) ||
                (miniorangeClientSecret != null && !miniorangeClientSecret.isEmpty()) ||
                (adPassword != null && !adPassword.isEmpty());
    }
}