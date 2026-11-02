package com.PassBanned.API.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service de gestion et d'invalidation des sessions côté serveur (Revocation List / Blacklist).
 * Permet d'invalider immédiatement les jetons JWT et sessions associées lors de la déconnexion
 * ou après 15 minutes d'inactivité de l'utilisateur.
 */
@Service
public class SessionRevocationService {

    private static final Logger logger = LoggerFactory.getLogger(SessionRevocationService.class);
    // Seuil de déconnexion automatique en cas d'inactivité : 20 minutes (1200 secondes)
    public static final long INACTIVITY_TIMEOUT_SECONDS = 20 * 60;

    // Map thread-safe stockant les tokens ou JTI révoqués avec leur heure d'expiration
    private final Map<String, Instant> revokedTokens = new ConcurrentHashMap<>();

    // Horodatage d'invalidation globale de session par utilisateur (email -> timestamp de déconnexion)
    private final Map<String, Instant> userSessionInvalidationTime = new ConcurrentHashMap<>();

    // Suivi de la dernière activité par session / JTI pour le délai d'inactivité de 15 minutes
    private final Map<String, Instant> sessionLastActivity = new ConcurrentHashMap<>();
    /**
     * Enregistre le démarrage d'une session active.
     */
    public void registerSessionActivity(String sessionId) {
        if (sessionId != null && !sessionId.isBlank()) {
            sessionLastActivity.put(sessionId, Instant.now());
        }
    }

    /**
     * Vérifie si la session a dépassé 15 minutes d'inactivité.
     * Si l'utilisateur est inactif depuis plus de 15 minutes, la session est automatiquement révoquée.
     * Si l'utilisateur est actif, l'horodatage d'activité est prolongé (sliding session).
     *
     * @return true si la session est expirée pour cause d'inactivité, false sinon.
     */

    public boolean checkAndUpdateInactivity(String sessionId, String token, Date issuedAt, String userEmail, Date expirationDate) {
        if (sessionId == null || sessionId.isBlank()) {
            return false;
        }

        Instant now = Instant.now();
        Instant lastActivity = sessionLastActivity.get(sessionId);
        // Si aucun horodatage préalable, initialiser avec la date d'émission ou maintenant
        if (lastActivity == null) {
            lastActivity = (issuedAt != null) ? issuedAt.toInstant() : now;
            sessionLastActivity.put(sessionId, now);
        }
        long idleSeconds = Duration.between(lastActivity, now).getSeconds();
        if (idleSeconds > INACTIVITY_TIMEOUT_SECONDS) {
            logger.warn("Session révoquée automatiquement pour inactivité (> 15 min): utilisateur={}, JTI={}", userEmail, sessionId);
            revokeToken(token, sessionId, expirationDate, userEmail);
            sessionLastActivity.remove(sessionId);
            return true;
        }
        // L'utilisateur est actif: prolonger l'inactivité de 15 minutes
        sessionLastActivity.put(sessionId, now);
        return false;
    }

    /**
     * Révoque un token d'accès et invalide la session associée.
     */
    public void revokeToken(String token, String jti, Date expirationDate, String userEmail) {
        Instant expiryInstant = (expirationDate != null)
                ? expirationDate.toInstant()
                : Instant.now().plusSeconds(INACTIVITY_TIMEOUT_SECONDS);

        if (token != null && !token.isBlank()) {
            revokedTokens.put(token, expiryInstant);
        }
        if (jti != null && !jti.isBlank()) {
            revokedTokens.put("jti:" + jti, expiryInstant);
            sessionLastActivity.remove(jti);
        }
        if (userEmail != null && !userEmail.isBlank()) {
            userSessionInvalidationTime.put(userEmail, Instant.now());
        }
        logger.info("Session révoquée avec succès pour: {}", userEmail != null ? userEmail : "anonyme");
    }

    /**
     * Vérifie si un token ou son identifiant unique JTI figure dans la liste de révocation.
     */
    public boolean isRevoked(String token, String jti, Date issuedAt, String userEmail) {
        if (token != null && revokedTokens.containsKey(token)) {
            return true;
        }
        if (jti != null && revokedTokens.containsKey("jti:" + jti)) {
            return true;
        }
        if (userEmail != null && issuedAt != null) {
            Instant invalidationTime = userSessionInvalidationTime.get(userEmail);
            if (invalidationTime != null && issuedAt.toInstant().isBefore(invalidationTime)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Purge automatiquement les tokens dont la durée de vie est dépassée et les sessions inactives anciennes.
     */
    @Scheduled(fixedRate = 300000)
    public void cleanExpiredRevocations() {
        Instant now = Instant.now();
        revokedTokens.entrySet().removeIf(entry -> entry.getValue().isBefore(now));
        sessionLastActivity.entrySet().removeIf(entry -> Duration.between(entry.getValue(), now).toHours() >= 2);
    }
}
