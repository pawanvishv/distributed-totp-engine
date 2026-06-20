package com.enterprise.totp.infrastructure.persistence.entity;

import com.enterprise.totp.domain.algorithm.HmacAlgorithm;
import com.enterprise.totp.infrastructure.persistence.converter.HmacAlgorithmConverter;
import jakarta.persistence.*;
import org.hibernate.annotations.Cache;
import org.hibernate.annotations.CacheConcurrencyStrategy;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;


@Entity
@Table(
    name = "user_mfa_profile",
    uniqueConstraints = @UniqueConstraint(
        name = "uq_user_mfa_profile_user_id",
        columnNames = "user_id"
    )
)
@Cache(usage = CacheConcurrencyStrategy.NONSTRICT_READ_WRITE)
public class UserMfaProfile {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false, length = 255)
    private String userId;

    @Column(name = "encrypted_secret", nullable = false, length = 512)
    private String encryptedSecret;

    @Convert(converter = HmacAlgorithmConverter.class)
    @Column(name = "algorithm", nullable = false, length = 20)
    private HmacAlgorithm algorithm;

    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

    @Version
    @Column(name = "version", nullable = false)
    private Long version = 0L;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    public UserMfaProfile() {}

    public UserMfaProfile(String userId, String encryptedSecret, HmacAlgorithm algorithm) {
        this.userId = userId;
        this.encryptedSecret = encryptedSecret;
        this.algorithm = algorithm;
        this.enabled = true;
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }

    public String getEncryptedSecret() { return encryptedSecret; }
    public void setEncryptedSecret(String encryptedSecret) { this.encryptedSecret = encryptedSecret; }

    public HmacAlgorithm getAlgorithm() { return algorithm; }
    public void setAlgorithm(HmacAlgorithm algorithm) { this.algorithm = algorithm; }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public Long getVersion() { return version; }
    public void setVersion(Long version) { this.version = version; }

    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
}


