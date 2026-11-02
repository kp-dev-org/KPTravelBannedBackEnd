package com.PassBanned.API.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

/**
 * Claims extraits du JWT officiel émis par FlyAsky (durée 10 minutes).
 *
 * sub : identifiant de l'utilisateur (la clé à associer dans vos tables)
 * email : adresse e-mail
 * email_verified : statut vérifié
 * role : rôle sur le gateway (non utilisé pour les autorisations métier)
 * sid : identifiant de session
 * iss : https://backend.flyasky.com
 * aud : api-gateway
 * exp : date d'expiration (10 minutes)
 */
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