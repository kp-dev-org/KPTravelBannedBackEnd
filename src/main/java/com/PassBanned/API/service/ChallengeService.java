package com.PassBanned.API.service;

import com.PassBanned.API.Model.User;
import com.PassBanned.API.dto.AuthChallenge;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service de gestion des challenges temporaires d'authentification.
 * Assure l'étape 2 du flux: mémorise le compte local ayant réussi le premier facteur,
 * dans l'attente de la validation du code OTP FlyAsky (second facteur).
 */
@Service
public class ChallengeService {

    // Durée de validité du challenge (10 minutes)
    private static final Duration CHALLENGE_TTL = Duration.ofMinutes(10);

    private final Map<String, AuthChallenge> challenges = new ConcurrentHashMap<>();

    /**
     * Crée un challenge temporaire pour un utilisateur local ayant passé le premier facteur.
     */
    public AuthChallenge createChallenge(User user) {
        String challengeId = UUID.randomUUID().toString();
        Instant now = Instant.now();
        AuthChallenge challenge = AuthChallenge.builder()
                .challengeId(challengeId)
                .userId(user.getId())
                .email(user.getEmail())
                .userName(user.getName())
                .role(user.getRole())
                .createdAt(now)
                .expiresAt(now.plus(CHALLENGE_TTL))
                .build();

        challenges.put(challengeId, challenge);
        return challenge;
    }

    /**
     * Récupère un challenge valide (non expiré).
     */
    public Optional<AuthChallenge> getValidChallenge(String challengeId) {
        if (challengeId == null || challengeId.isBlank()) {
            return Optional.empty();
        }
        AuthChallenge challenge = challenges.get(challengeId);
        if (challenge == null) {
            return Optional.empty();
        }
        if (challenge.isExpired()) {
            challenges.remove(challengeId);
            return Optional.empty();
        }
        return Optional.of(challenge);
    }

    /**
     * Consomme (invalide) le challenge une fois la liaison établie.
     */
    public void consumeChallenge(String challengeId) {
        if (challengeId != null) {
            challenges.remove(challengeId);
        }
    }

    /**
     * Nettoyage régulier des challenges expirés toutes les 2 minutes.
     */
    @Scheduled(fixedRate = 120000)
    public void cleanExpiredChallenges() {
        Instant now = Instant.now();
        challenges.entrySet().removeIf(entry -> entry.getValue().getExpiresAt().isBefore(now));
    }
}
