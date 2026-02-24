package com.example.darkknight.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SamlConfigDto {
    private Boolean samlEnabled;

    // IdP inputs provided by the tenant admin
    private String samlIdpEntityId; // IdP Entity ID / Issuer
    private String samlIdpLoginUrl; // SAML Login URL (SSO endpoint)
    private String samlIdpCertificate; // X.509 certificate (PEM text, pasted by admin)

    // SP metadata (auto-generated, read-only in UI)
    private String samlSpEntityId;
    private String samlSpAcsUrl;
    private String samlSpBinding;
    private String samlSpNameIdFormat;
}