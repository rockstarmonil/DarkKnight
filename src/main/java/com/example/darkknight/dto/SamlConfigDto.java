package com.example.darkknight.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SamlConfigDto {
    private Boolean samlEnabled;
    private String samlIdpLoginUrl;
    private String samlSpEntityId;
    private String samlSpAcsUrl;
    private String samlSpBinding;
    private String samlSpNameIdFormat;
    private String samlCertificatePath;
}