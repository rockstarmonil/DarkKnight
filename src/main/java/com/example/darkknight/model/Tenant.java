package com.example.darkknight.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(name = "tenants")
public class Tenant {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name; // Company name

    @Column(unique = true, nullable = false)
    private String subdomain; // e.g., "acme" -> acme.localhost:8080

    @Column(nullable = false)
    private String status = "ACTIVE"; // ACTIVE, SUSPENDED, TRIAL

    @Column(name = "max_users")
    private Integer maxUsers = 20; // Default limit: 20 users per tenant

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    // Tenant owner/admin (the first admin who created this tenant)
    @ManyToOne
    @JoinColumn(name = "owner_id")
    private User owner;

    // All users belonging to this tenant
    @OneToMany(mappedBy = "tenant", cascade = CascadeType.ALL)
    private List<User> users;

    // Branding settings
    private String logoUrl;
    private String primaryColor = "#9d00ff";
    private String secondaryColor = "#ff00ff";

    // Default constructor
    public Tenant() {}

    // Constructor for easy creation
    public Tenant(String name, String subdomain, User owner) {
        this.name = name;
        this.subdomain = subdomain;
        this.owner = owner;
        this.status = "ACTIVE";
        this.maxUsers = 20;
    }

    // --- Getters and Setters ---
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getSubdomain() { return subdomain; }
    public void setSubdomain(String subdomain) { this.subdomain = subdomain.toLowerCase(); }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public Integer getMaxUsers() { return maxUsers; }
    public void setMaxUsers(Integer maxUsers) { this.maxUsers = maxUsers; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }

    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }

    public User getOwner() { return owner; }
    public void setOwner(User owner) { this.owner = owner; }

    public List<User> getUsers() { return users; }
    public void setUsers(List<User> users) { this.users = users; }

    public String getLogoUrl() { return logoUrl; }
    public void setLogoUrl(String logoUrl) { this.logoUrl = logoUrl; }

    public String getPrimaryColor() { return primaryColor; }
    public void setPrimaryColor(String primaryColor) { this.primaryColor = primaryColor; }

    public String getSecondaryColor() { return secondaryColor; }
    public void setSecondaryColor(String secondaryColor) { this.secondaryColor = secondaryColor; }

    // --- Lifecycle Hooks ---
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
        if (subdomain != null) {
            subdomain = subdomain.toLowerCase();
        }
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    // --- Helper Methods ---
    public int getCurrentUserCount() {
        return users != null ? users.size() : 0;
    }

    public boolean hasReachedUserLimit() {
        return getCurrentUserCount() >= maxUsers;
    }

    public boolean isActive() {
        return "ACTIVE".equalsIgnoreCase(status);
    }

    public boolean isSuspended() {
        return "SUSPENDED".equalsIgnoreCase(status);
    }
}