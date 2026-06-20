package com.enterprise.totp.infrastructure.persistence.repository;

import com.enterprise.totp.infrastructure.persistence.entity.UserMfaProfile;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.QueryHints;
import org.springframework.stereotype.Repository;

import jakarta.persistence.QueryHint;
import java.util.Optional;


@Repository
public interface UserMfaProfileRepository extends JpaRepository<UserMfaProfile, Long> {

    @QueryHints({
        @QueryHint(name = "org.hibernate.cacheable", value = "true")
    })
    Optional<UserMfaProfile> findByUserId(String userId);
}

