package com.PassBanned.API.security;

import com.PassBanned.API.Model.User;
import com.PassBanned.API.dto.FlyAskyClaims;
import com.PassBanned.API.repository.UserRepository;
import com.PassBanned.API.service.FlyAskyAuthService;
import com.PassBanned.API.service.SessionRevocationService;
import com.PassBanned.API.service.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.Optional;

/**
 * Filtre de sécurité assurant la validation des jetons JWT.
 * Conforme aux directives :
 * 1. La session d'authentification est gérée par l'API FlyAsky (JWT FlyAsky transmis dans Authorization: Bearer).
 * 2. SEUL LE RÔLE DE L'UTILISATEUR DANS LA BASE LOCALE est appliqué pour le contrôle d'accès.
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    public static final String COOKIE_NAME = "_sec_session";

    @Autowired
    private JwtTokenProvider tokenProvider;

    @Autowired
    private UserService userService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private SessionRevocationService sessionRevocationService;

    @Autowired
    private FlyAskyAuthService flyAskyAuthService;

    @Override
    protected void doFilterInternal(@NotNull HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull FilterChain filterChain)
            throws ServletException, IOException {
        try {
            String token = getJwtFromRequest(request);

            if (StringUtils.hasText(token)) {
                // CAS 1 : Jeton JWT FlyAsky (validité 10 minutes)
                if (isFlyAskyJwt(token)) {
                    processFlyAskyAuthentication(token, request);
                }
                // CAS 2 : Jeton local (cookie HttpOnly _sec_session ou rétro-compatibilité)
                else if (tokenProvider.validateToken(token)) {
                    processLocalAuthentication(token, request);
                }
            }
        } catch (Exception ex) {
            logger.error("Erreur lors de l'authentification dans le filtre de sécurité", ex);
        }
        filterChain.doFilter(request, response);
    }

    /**
     * Traite un JWT émis par FlyAsky :
     * - Vérifie l'expiration, l'émetteur et l'audience
     * - Retrouve le compte local par sub FlyAsky ou email
     * - APPLIQUE EXCLUSIVEMENT LE RÔLE DE LA BASE LOCALE
     */
    private void processFlyAskyAuthentication(String jwt, HttpServletRequest request) {
        try {
            FlyAskyClaims claims = flyAskyAuthService.parseAndVerifyJwt(jwt);
            // Rechercher l'utilisateur dans la base locale (par son sub FlyAsky ou email)
            Optional<User> localUserOpt = Optional.empty();
            if (claims.getSub() != null) {
                localUserOpt = userRepository.findByFlyAskySub(claims.getSub());
            }
            if (localUserOpt.isEmpty() && claims.getEmail() != null) {
                localUserOpt = userRepository.findByEmail(claims.getEmail().toLowerCase());
            }
            if (localUserOpt.isEmpty()) {
                logger.warn("JWT FlyAsky valide mais aucun utilisateur local correspondant: sub={}, email={}",
                        claims.getSub(), claims.getEmail());
                return;
            }
            User localUser = localUserOpt.get();
            // Vérifier que le compte local est actif
            if (localUser.getStatus() != User.Status.ACTIVE) {
                logger.warn("Compte local inactif pour l'utilisateur FlyAsky: {}", localUser.getEmail());
                return;
            }
            // Vérifier la liste de révocation et la fenêtre d'inactivité de 20 minutes
            String jti = claims.getSid() != null ? claims.getSid() : claims.getSub();
            Date expDate = claims.getExpiration();
            Date issDate = claims.getIssuedAt();
            if (sessionRevocationService.isRevoked(jwt, jti, issDate, localUser.getEmail())) {
                logger.warn("Accès refusé: token FlyAsky révoqué pour {}", localUser.getEmail());
                return;
            }
            if (sessionRevocationService.checkAndUpdateInactivity(jti, jwt, issDate, localUser.getEmail(), expDate)) {
                logger.warn("Accès refusé: session FlyAsky révoquée suite à inactivité pour {}", localUser.getEmail());
                return;
            }
            // CRITIQUE : Seul le rôle de l'utilisateur dans la base locale est utilisé
            String localRoleAuthority = "ROLE_" + localUser.getRole().name();
            List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(localRoleAuthority));

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    localUser.getEmail(),
                    null,
                    authorities
            );
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);

            logger.debug("Authentification FlyAsky validée avec rôle local {} pour {}", localRoleAuthority, localUser.getEmail());

        } catch (SecurityException se) {
            logger.error("ALERTE SÉCURITÉ: Requête rejetée car l'authenticité du JWT FlyAsky a échoué (JWKS): {}", se.getMessage());
            SecurityContextHolder.clearContext();
        } catch (Exception e) {
            logger.warn("Échec validation JWT FlyAsky: {}", e.getMessage());
            SecurityContextHolder.clearContext();
        }
    }

    /**
     * Traite un jeton de session émis localement.
     */
    private void processLocalAuthentication(String jwt, HttpServletRequest request) {
        String username = tokenProvider.getUsernameFromToken(jwt);
        String jti = tokenProvider.getJtiFromToken(jwt);
        Date issuedAt = tokenProvider.getIssuedAtDateFromToken(jwt);
        Date expiryDate = tokenProvider.getExpirationDateFromToken(jwt);

        if (sessionRevocationService.isRevoked(jwt, jti, issuedAt, username)) {
            logger.warn("Accès refusé: token révoqué pour " + username);
            return;
        }
        if (sessionRevocationService.checkAndUpdateInactivity(jti, jwt, issuedAt, username, expiryDate)) {
            logger.warn("Accès refusé: session révoquée suite à 15 minutes d'inactivité pour " + username);
            return;
        }
        UserDetails userDetails = userService.loadUserByUsername(username);
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private boolean isFlyAskyJwt(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length >= 2) {
                String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
                return payload.contains("https://backend.flyasky.com") || payload.contains("api-gateway") || payload.contains("@flyasky.com");
            }
        } catch (Exception ignored) {}
        return false;
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        // 1. Extraction prioritaire depuis l'en-tête Authorization: Bearer <token>
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }

        // 2. Extraction depuis le cookie HttpOnly (_sec_session)
        if (request.getCookies() != null) {
            for (jakarta.servlet.http.Cookie cookie : request.getCookies()) {
                if (COOKIE_NAME.equals(cookie.getName())
                        || "passbanned_jwt".equals(cookie.getName())
                        || "jwt_token".equals(cookie.getName())) {
                    if (StringUtils.hasText(cookie.getValue())) {
                        return cookie.getValue();
                    }
                }
            }
        }

        return null;
    }
}
