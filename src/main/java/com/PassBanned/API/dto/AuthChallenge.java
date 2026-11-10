package com.PassBanned.API.dto;

import com.PassBanned.API.Model.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthChallenge {
    private String challengeId;
    private Long userId;
    private String email;
    private String userName;
    private User.Role role;
    private Instant createdAt;
    private Instant expiresAt;

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }
}
