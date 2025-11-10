// File: com.example.darkknight.security.CustomUserDetails.java

package com.example.darkknight.security;

import com.example.darkknight.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import java.util.Collection;
import java.util.Collections;

public class CustomUserDetails implements UserDetails {

    private final User user;
    private final Long tenantId;
    private final String tenantSubdomain;

    public CustomUserDetails(User user) {
        this.user = user;
        // Safely extract tenant info
        this.tenantId = user.getTenant() != null ? user.getTenant().getId() : null;
        this.tenantSubdomain = user.getTenant() != null ? user.getTenant().getSubdomain() : null;
    }

    public Long getTenantId() {
        return tenantId;
    }

    public String getTenantSubdomain() {
        return tenantSubdomain;
    }

    // Standard UserDetails methods
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(new SimpleGrantedAuthority(user.getRole()));
    }

    @Override
    public String getPassword() {
        return user.getPassword(); // Encoded password
    }

    @Override
    public String getUsername() {
        return user.getUsername(); // Email
    }

    @Override
    public boolean isAccountNonExpired() { return true; }

    @Override
    public boolean isAccountNonLocked() { return true; }

    @Override
    public boolean isCredentialsNonExpired() { return true; }

    @Override
    public boolean isEnabled() { return user.isEnabled(); }
}