package com.example.darkknight.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class OAuthConfigDto {
    private Boolean oauthEnabled;
    private String oauthClientId;
    private String oauthClientSecret;
    private String oauthRedirectUri;
    private String oauthAuthorizationUrl;
    private String oauthTokenUrl;
    private String oauthUserinfoUrl;
}