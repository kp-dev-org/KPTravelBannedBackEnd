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

    // Suivi de la dernière activité par session / JTI pour le délai d'inactivité de 20 minutes
    private final Map<String, Instant> sessionLastActivity = new ConcurrentHashMap<>();

    // Suivi de la dernière activité par utilisateur (email -> Instant) pour bloquer les renouvellements après 20 min
    private final Map<String, Instant> userLastActivity = new ConcurrentHashMap<>();

    /**
     * Enregistre le démarrage ou l'activité d'une session active.
     */
    public void registerSessionActivity(String sessionId) {
        registerSessionActivity(sessionId, null);
    }

    public void registerSessionActivity(String sessionId, String userEmail) {
        Instant now = Instant.now();
        if (sessionId != null && !sessionId.isBlank()) {
            sessionLastActivity.put(sessionId, now);
        }
        if (userEmail != null && !userEmail.isBlank()) {
            userLastActivity.put(userEmail.trim().toLowerCase(), now);
        }
    }

    /**
     * Vérifie si un utilisateur ou une session a dépassé les 20 minutes d'inactivité.
     */
    public boolean isUserInactive(String userEmail, String sessionId) {
        Instant now = Instant.now();
        if (userEmail != null && !userEmail.isBlank()) {
            Instant lastUser = userLastActivity.get(userEmail.trim().toLowerCase());
            if (lastUser != null && Duration.between(lastUser, now).getSeconds() > INACTIVITY_TIMEOUT_SECONDS) {
                return true;
            }
        }
        if (sessionId != null && !sessionId.isBlank()) {
            Instant lastSession = sessionLastActivity.get(sessionId);
            if (lastSession != null && Duration.between(lastSession, now).getSeconds() > INACTIVITY_TIMEOUT_SECONDS) {
                return true;
            }
        }
        return false;
    }

    /**
     * Révoque explicitement une session suite à 20 minutes d'inactivité.
     */
    public void revokeSessionDueToInactivity(String userEmail, String token, String sessionId) {
        Instant now = Instant.now();
        if (userEmail != null && !userEmail.isBlank()) {
            userSessionInvalidationTime.put(userEmail.trim().toLowerCase(), now);
            userLastActivity.remove(userEmail.trim().toLowerCase());
        }
        if (sessionId != null && !sessionId.isBlank()) {
            sessionLastActivity.remove(sessionId);
            revokedTokens.put("jti:" + sessionId, now.plusSeconds(INACTIVITY_TIMEOUT_SECONDS));
        }
        if (token != null && !token.isBlank()) {
            revokedTokens.put(token, now.plusSeconds(INACTIVITY_TIMEOUT_SECONDS));
        }
        logger.warn("Session révoquée avec succès pour cause d'inactivité (20 min) pour: {}", userEmail);
    }

    /**
     * Vérifie si la session a dépassé 20 minutes d'inactivité.
     * Si l'utilisateur est inactif depuis plus de 20 minutes, la session est automatiquement révoquée.
     * Si l'utilisateur est actif, l'horodatage d'activité est prolongé (sliding session).
     *
     * @return true si la session est expirée pour cause d'inactivité, false sinon.
     */
    public boolean checkAndUpdateInactivity(String sessionId, String token, Date issuedAt, String userEmail, Date expirationDate) {
        Instant now = Instant.now();

        // 1. Contrôle préalable par compte utilisateur
        if (userEmail != null && !userEmail.isBlank()) {
            Instant lastUser = userLastActivity.get(userEmail.trim().toLowerCase());
            if (lastUser != null && Duration.between(lastUser, now).getSeconds() > INACTIVITY_TIMEOUT_SECONDS) {
                logger.warn("Session révoquée automatiquement pour inactivité (> 20 min) pour l'utilisateur: {}", userEmail);
                revokeSessionDueToInactivity(userEmail, token, sessionId);
                return true;
            }
            userLastActivity.put(userEmail.trim().toLowerCase(), now);
        }

        // 2. Contrôle par sessionId / JTI
        if (sessionId != null && !sessionId.isBlank()) {
            Instant lastActivity = sessionLastActivity.get(sessionId);

            // Si aucun horodatage préalable, initialiser avec la date d'émission ou maintenant
            if (lastActivity == null) {
                lastActivity = (issuedAt != null) ? issuedAt.toInstant() : now;
                sessionLastActivity.put(sessionId, now);
            }

            long idleSeconds = Duration.between(lastActivity, now).getSeconds();
            if (idleSeconds > INACTIVITY_TIMEOUT_SECONDS) {
                logger.warn("Session révoquée automatiquement pour inactivité (> 20 min): utilisateur={}, JTI={}", userEmail, sessionId);
                revokeSessionDueToInactivity(userEmail, token, sessionId);
                return true;
            }

            sessionLastActivity.put(sessionId, now);
        }

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
            userSessionInvalidationTime.put(userEmail.trim().toLowerCase(), Instant.now());
            userLastActivity.remove(userEmail.trim().toLowerCase());
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
