package com.example.darkknight.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class JwtConfigDto {
    private Boolean jwtEnabled;
    private String miniorangeLoginUrl;
    private String miniorangeClientId;
    private String miniorangeClientSecret;
    private String miniorangeRedirectUri;
    /** HMAC algorithm: "HS256" (default), "HS384", or "HS512" */
    private String jwtAlgorithm;
}