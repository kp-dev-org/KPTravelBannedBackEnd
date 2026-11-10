package com.PassBanned.API.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FlyAskyClaims {
    private String sub;
    private String email;
    private boolean emailVerified;
    private String role;
    private String sid;
    private String issuer;
    private String audience;
    private Date issuedAt;
    private Date expiration;

    public boolean isExpired() {
        return expiration != null && expiration.before(new Date());
    }
}