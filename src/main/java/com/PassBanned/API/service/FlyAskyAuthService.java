package com.PassBanned.API.service;

import com.PassBanned.API.dto.FlyAskyClaims;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.TimeUnit;

/**
 * Service client pour l'API d'authentification officielle FlyAsky (auth-v1).
 * Conforme aux directives du document d'intégration :
 *
 * 1. POST /email-otp/send-verification-otp : Demande du code OTP à 6 chiffres (valable 5 min)
 * 2. POST /sign-in/email-otp : Connexion avec OTP -> renvoie le jeton de SESSION (set-auth-token)
 * 3. GET /token : Échange session -> JWT d'accès métier (valable 10 min) via Authorization: Bearer <session>
 * 4. GET /get-session : Consultation de la session courante
 * 5. GET /jwks : Clés publiques pour vérifier l'authenticité cryptographique du JWT
 * 6. POST /sign-out : Révocation et destruction de la session
 */
@Service
public class FlyAskyAuthService {

    private static final Logger logger = LoggerFactory.getLogger(FlyAskyAuthService.class);
    private static final MediaType JSON_MEDIA_TYPE = MediaType.parse("application/json; charset=utf-8");

    @Value("${flyasky.auth.base-url:https://backend.flyasky.com/auth/v1/api/auth}")
    private String baseUrl;

    @Value("${flyasky.auth.jwks-url:https://backend.flyasky.com/auth/v1/api/auth/jwks}")
    private String jwksUrl;

    @Value("${flyasky.auth.issuer:https://backend.flyasky.com}")
    private String expectedIssuer;

    @Value("${flyasky.auth.audience:api-gateway}")
    private String expectedAudience;

    private final OkHttpClient httpClient;
    private final ObjectMapper objectMapper;

    // Cache des clés publiques JWKS FlyAsky
    private volatile JWKSet cachedJwkSet;
    private volatile long jwkSetLastFetched = 0;
    private static final long JWKS_CACHE_TTL_MS = 60 * 60 * 1000; // Cache 1 heure

    public FlyAskyAuthService() {
        this.httpClient = new OkHttpClient.Builder()
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(10, TimeUnit.SECONDS)
                .writeTimeout(10, TimeUnit.SECONDS)
                .followRedirects(true)
                .build();
        this.objectMapper = new ObjectMapper();
    }

    /**
     * 1. Demander un code OTP par e-mail
     * POST /email-otp/send-verification-otp
     * Corps: {"email":"prenom.nom@flyasky.com","type":"sign-in"}
     * Réponse: {"success":true} (valable 5 minutes)
     */
    public boolean sendVerificationOtp(String email) throws IOException {
        String cleanEmail = email.trim().toLowerCase();

        // Règle d'accès FlyAsky : Seules les adresses @flyasky.com reçoivent un code
        if (!cleanEmail.endsWith("@flyasky.com")) {
            logger.warn("Adresse hors domaine @flyasky.com : {}", cleanEmail);
            throw new IllegalArgumentException("Seules les adresses e-mail @flyasky.com sont acceptées par le portail FlyAsky.");
        }

        String url = baseUrl + "/email-otp/send-verification-otp";
        String payload = objectMapper.writeValueAsString(new OtpRequest(cleanEmail, "sign-in"));

        Request request = new Request.Builder()
                .url(url)
                .post(RequestBody.create(payload, JSON_MEDIA_TYPE))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .build();

        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                String errorBody = response.body() != null ? response.body().string() : "";
                logger.error("Échec envoi OTP FlyAsky (HTTP {}): {}", response.code(), errorBody);
                throw new IOException("Erreur passerelle FlyAsky lors de l'envoi de l'OTP (HTTP " + response.code() + ")");
            }
            logger.info("Code OTP FlyAsky envoyé avec succès à: {}", cleanEmail);
            return true;
        }
    }

    /**
     * 2. Se connecter avec le code OTP
     * POST /sign-in/email-otp
     * Corps: {"email":"…","otp":"123456"}
     * Réponse: Jeton de SESSION dans l'en-tête set-auth-token ou cookie auth-session.session_token
     */
    public String signInWithEmailOtp(String email, String otp) throws IOException {
        String cleanEmail = email.trim().toLowerCase();
        String cleanOtp = otp.trim();

        String url = baseUrl + "/sign-in/email-otp";
        String payload = objectMapper.writeValueAsString(new SignInOtpRequest(cleanEmail, cleanOtp));

        Request request = new Request.Builder()
                .url(url)
                .post(RequestBody.create(payload, JSON_MEDIA_TYPE))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .build();

        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                String errorBody = response.body() != null ? response.body().string() : "";
                logger.warn("Échec validation OTP FlyAsky (HTTP {}): {}", response.code(), errorBody);
                throw new IllegalArgumentException("Code OTP FlyAsky incorrect ou expiré (durée 5 minutes).");
            }

            // Récupérer le jeton de session depuis set-auth-token ou cookie
            String sessionToken = response.header("set-auth-token");
            if (sessionToken == null || sessionToken.isBlank()) {
                for (String cookie : response.headers("Set-Cookie")) {
                    if (cookie.contains("auth-session.session_token=")) {
                        int start = cookie.indexOf("auth-session.session_token=") + "auth-session.session_token=".length();
                        int end = cookie.indexOf(";", start);
                        sessionToken = (end != -1) ? cookie.substring(start, end) : cookie.substring(start);
                        break;
                    }
                }
            }

            if (sessionToken == null || sessionToken.isBlank()) {
                String body = response.body() != null ? response.body().string() : "";
                try {
                    JsonNode node = objectMapper.readTree(body);
                    if (node.has("token")) {
                        sessionToken = node.get("token").asText();
                    } else if (node.has("sessionToken")) {
                        sessionToken = node.get("sessionToken").asText();
                    }
                } catch (Exception ignored) {}
            }

            if (sessionToken == null || sessionToken.isBlank()) {
                throw new IOException("Jeton de session FlyAsky introuvable dans la réponse.");
            }

            return sessionToken;
        }
    }

    /**
     * 3. Échanger le jeton de SESSION contre le JWT métier (valable 10 minutes)
     * GET /token
     * En-tête: Authorization: Bearer <jeton de session>
     * Réponse: {"token":"<jwt>"}
     *
     * À chaque fois qu'on veut renouveler le token lorsqu'une session est ouverte,
     * on effectue cet appel GET /token, puis on valide son authenticité via JWKS.
     */
    public String exchangeSessionForJwt(String sessionToken) throws IOException {
        String url = baseUrl + "/token";

        Request request = new Request.Builder()
                .url(url)
                .get()
                .header("Authorization", "Bearer " + sessionToken)
                .header("Accept", "application/json")
                .build();

        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                String err = response.body() != null ? response.body().string() : "";
                logger.error("Échec obtention JWT FlyAsky via GET /token (HTTP {}): {}", response.code(), err);
                throw new IOException("Impossible d'obtenir le JWT FlyAsky via GET /token (HTTP " + response.code() + ")");
            }

            String body = response.body() != null ? response.body().string() : "{}";
            JsonNode node = objectMapper.readTree(body);
            if (node.has("token")) {
                String jwt = node.get("token").asText();
                // Vérification cryptographique immédiate de l'authenticité du JWT reçu via JWKS
                verifyJwtSignatureWithJwks(jwt);
                logger.info("JWT FlyAsky renouvelé via GET /token et vérifié avec succès par JWKS.");
                return jwt;
            }
            throw new IOException("Champ 'token' manquant dans la réponse FlyAsky /token");
        }
    }

    public record FlyAskySessionConsultation(
            JsonNode session,
            JsonNode user
    ) {}

    /**
     * 4. Session courante (Consultation de session uniquement)
     * GET /get-session
     * En-tête: Authorization: Bearer <jeton de session> ou cookie
     * Réponse: session et utilisateur
     *
     * Note: GET /get-session permet de consulter la session et l'utilisateur.
     * Pour obtenir le token ou le renouveler, on fait TOUJOURS GET /token.
     */
    public FlyAskySessionConsultation getSession(String sessionToken) throws IOException {
        String url = baseUrl + "/get-session";

        Request request = new Request.Builder()
                .url(url)
                .get()
                .header("Authorization", "Bearer " + sessionToken)
                .header("Accept", "application/json")
                .build();

        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                String errorBody = response.body() != null ? response.body().string() : "";
                logger.error("Session FlyAsky inactive ou expirée (HTTP {}): {}", response.code(), errorBody);
                throw new IOException("Session FlyAsky inactive ou expirée (HTTP " + response.code() + ")");
            }

            String body = response.body() != null ? response.body().string() : "{}";
            JsonNode root = objectMapper.readTree(body);

            JsonNode sessionNode = root.has("session") ? root.get("session") : root;
            JsonNode userNode = root.has("user") ? root.get("user") : null;

            return new FlyAskySessionConsultation(sessionNode, userNode);
        }
    }

    /**
     * 5. Clés publiques JWKS pour vérifier l'authenticité du JWT
     * GET /jwks
     * Réponse: {"keys":[{"kid":...,"kty":...,"x":...}]}
     */
    public JWKSet fetchJwks() throws IOException {
        long now = System.currentTimeMillis();
        if (cachedJwkSet != null && (now - jwkSetLastFetched) < JWKS_CACHE_TTL_MS) {
            return cachedJwkSet;
        }

        String targetUrl = (jwksUrl != null && !jwksUrl.isBlank()) ? jwksUrl : baseUrl + "/jwks";
        Request request = new Request.Builder()
                .url(targetUrl)
                .get()
                .header("Accept", "application/json")
                .build();

        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                String err = response.body() != null ? response.body().string() : "";
                logger.error("Échec récupération des clés JWKS FlyAsky (HTTP {}): {}", response.code(), err);
                throw new IOException("Impossible de récupérer les clés publiques JWKS FlyAsky (HTTP " + response.code() + ")");
            }

            String jwksJson = response.body() != null ? response.body().string() : "{}";
            try {
                JWKSet jwkSet = JWKSet.parse(jwksJson);
                this.cachedJwkSet = jwkSet;
                this.jwkSetLastFetched = now;
                logger.info("Clés publiques JWKS FlyAsky rechargées avec succès ({} clés disponibles)", jwkSet.getKeys().size());
                return jwkSet;
            } catch (java.text.ParseException pe) {
                throw new IOException("Format JWKS JSON invalide: " + pe.getMessage(), pe);
            }
        }
    }

    /**
     * Vérifie la signature cryptographique du JWT avec le JWKS de FlyAsky.
     * Si la signature ou l'authenticité échoue, le système REJETTE immédiatement le token (SecurityException).
     */
    public boolean verifyJwtSignatureWithJwks(String jwtToken) {
        if (jwtToken == null || jwtToken.isBlank()) {
            throw new SecurityException("Authenticité rejetée : Token JWT FlyAsky manquant.");
        }

        try {
            SignedJWT signedJWT = SignedJWT.parse(jwtToken);
            String kid = signedJWT.getHeader().getKeyID();
            JWSAlgorithm algorithm = signedJWT.getHeader().getAlgorithm();

            JWKSet jwkSet;
            try {
                jwkSet = fetchJwks();
            } catch (Exception e) {
                logger.error("Serveur JWKS FlyAsky injoignable pour la vérification: {}", e.getMessage());
                throw new SecurityException("Authenticité rejetée : Impossible de joindre le serveur JWKS FlyAsky (" + e.getMessage() + ")");
            }

            JWK matchingKey = null;
            if (kid != null) {
                matchingKey = jwkSet.getKeyByKeyId(kid);
            }
            if (matchingKey == null && !jwkSet.getKeys().isEmpty()) {
                matchingKey = jwkSet.getKeys().get(0);
            }

            if (matchingKey == null) {
                logger.error("ALERTE SÉCURITÉ: Aucune clé publique correspondante dans le JWKS FlyAsky (kid={})", kid);
                throw new SecurityException("Authenticité rejetée : Clé publique introuvable dans le JWKS FlyAsky (kid=" + kid + ")");
            }

            JWSVerifier verifier = createVerifier(matchingKey);
            if (verifier == null) {
                logger.error("ALERTE SÉCURITÉ: Type de clé publique non pris en charge (type={})", matchingKey.getKeyType());
                throw new SecurityException("Authenticité rejetée : Type de clé publique non supporté (" + matchingKey.getKeyType() + ")");
            }

            boolean isValid = signedJWT.verify(verifier);
            if (!isValid) {
                logger.error("ALERTE SÉCURITÉ CRITIQUE: Signature cryptographique JWT FlyAsky non valide via JWKS ! Le token a été altéré ou falsifié.");
                throw new SecurityException("Signature cryptographique du JWT non authentique selon le JWKS FlyAsky. Token rejeté.");
            }

            logger.info("Authenticité du JWT FlyAsky validée avec succès via JWKS (kid={}, alg={})", kid, algorithm);
            return true;

        } catch (SecurityException se) {
            throw se;
        } catch (Exception ex) {
            logger.error("ALERTE SÉCURITÉ: Échec de vérification cryptographique du JWT: {}", ex.getMessage());
            throw new SecurityException("Authenticité du JWT FlyAsky non valide : " + ex.getMessage(), ex);
        }
    }

    private JWSVerifier createVerifier(JWK jwk) {
        try {
            if (jwk instanceof RSAKey rsaKey) {
                return new RSASSAVerifier(rsaKey);
            } else if (jwk instanceof ECKey ecKey) {
                return new ECDSAVerifier(ecKey);
            } else if (jwk instanceof OctetKeyPair okp) {
                return new Ed25519Verifier(okp);
            }
        } catch (Exception e) {
            logger.error("Impossible d'initialiser le vérificateur JWS: {}", e.getMessage());
        }
        return null;
    }

    /**
     * 6. Se déconnecter (Révocation de la session)
     * POST /sign-out
     * En-tête: Authorization: Bearer <jeton de session>
     * Réponse: session détruite ; ses JWT sont refusés par le gateway
     */
    public void signOut(String sessionToken) {
        if (sessionToken == null || sessionToken.isBlank()) return;
        try {
            Request request = new Request.Builder()
                    .url(baseUrl + "/sign-out")
                    .post(RequestBody.create("", null))
                    .header("Authorization", "Bearer " + sessionToken)
                    .build();
            try (Response resp = httpClient.newCall(request).execute()) {
                logger.info("Session FlyAsky révoquée avec succès: status={}", resp.code());
            }
        } catch (Exception e) {
            logger.warn("Avis lors du sign-out FlyAsky: {}", e.getMessage());
        }
    }

    /**
     * Décode et valide la charge utile d'un JWT FlyAsky.
     * Claims (§3 du document) :
     * sub, email, email_verified, role, sid, iss, aud, iat, exp
     */
    public FlyAskyClaims parseClaims(String jwtToken, boolean verifyExpiration) {
        if (jwtToken == null || jwtToken.isBlank()) {
            throw new IllegalArgumentException("JWT FlyAsky manquant.");
        }

        try {
            String[] parts = jwtToken.split("\\.");
            if (parts.length < 2) {
                throw new IllegalArgumentException("Format de JWT invalide.");
            }

            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            JsonNode payload = objectMapper.readTree(payloadJson);

            String sub = payload.has("sub") ? payload.get("sub").asText() : null;
            String email = payload.has("email") ? payload.get("email").asText() : null;
            boolean emailVerified = payload.has("email_verified") && payload.get("email_verified").asBoolean();
            String role = payload.has("role") ? payload.get("role").asText() : "user";
            String sid = payload.has("sid") ? payload.get("sid").asText() : null;
            String iss = payload.has("iss") ? payload.get("iss").asText() : null;
            String aud = payload.has("aud") ? payload.get("aud").asText() : null;

            long expSeconds = payload.has("exp") ? payload.get("exp").asLong() : 0;
            long iatSeconds = payload.has("iat") ? payload.get("iat").asLong() : 0;

            Date exp = new Date(expSeconds * 1000);
            Date iat = new Date(iatSeconds * 1000);

            if (verifyExpiration && exp.before(new Date())) {
                throw new IllegalArgumentException("Le JWT FlyAsky est expiré.");
            }

            return FlyAskyClaims.builder()
                    .sub(sub)
                    .email(email)
                    .emailVerified(emailVerified)
                    .role(role)
                    .sid(sid)
                    .issuer(iss)
                    .audience(aud)
                    .issuedAt(iat)
                    .expiration(exp)
                    .build();
        } catch (IllegalArgumentException iae) {
            throw iae;
        } catch (Exception e) {
            throw new IllegalArgumentException("Impossible de lire les claims du JWT: " + e.getMessage());
        }
    }

    public FlyAskyClaims parseAndVerifyJwt(String jwtToken) {
        // 1. Vérification de la signature cryptographique du JWT avec le JWKS public FlyAsky
        verifyJwtSignatureWithJwks(jwtToken);
        // 2. Vérification des claims et de l'expiration
        return parseClaims(jwtToken, true);
    }

    public FlyAskyClaims extractClaimsIgnoreExpiration(String jwtToken) {
        return parseClaims(jwtToken, false);
    }

    private record OtpRequest(String email, String type) {}
    private record SignInOtpRequest(String email, String otp) {}
}
