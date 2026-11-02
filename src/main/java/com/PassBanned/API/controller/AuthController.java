package com.PassBanned.API.controller;

import com.PassBanned.API.Model.User;
import com.PassBanned.API.dto.*;
import com.PassBanned.API.repository.UserRepository;
import com.PassBanned.API.security.JwtAuthenticationFilter;
import com.PassBanned.API.security.JwtTokenProvider;
import com.PassBanned.API.service.*;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Contrôleur d'authentification à deux facteurs intégrant FlyAsky :
 * 1. Premier facteur : identifiants de la base locale (e-mail + mot de passe)
 * 2. Deuxième facteur : API FlyAsky (OTP par e-mail, session, JWT 10 min)
 * 3. Contrôle des accès métier : exclusivement basé sur le rôle de la base locale.
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    public static final String COOKIE_NAME = JwtAuthenticationFilter.COOKIE_NAME;
    public static final String SESSION_COOKIE_NAME = "auth-session.session_token";

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserService userService;

    @Autowired
    private JwtTokenProvider tokenProvider;

    @Autowired
    private SessionRevocationService sessionRevocationService;

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private ChallengeService challengeService;

    @Autowired
    private FlyAskyAuthService flyAskyAuthService;

    /**
     * ÉTAPE 1 : Connexion locale (Premier facteur)
     * Le backend vérifie l'email et le mot de passe dans la base locale existante.
     * Si OK, création d'un challenge temporaire et déclenchement de l'envoi de l'OTP FlyAsky.
     * Aucun accès métier n'est encore accordé.
     */
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> authenticateUser(
            @Valid @RequestBody AuthRequest authRequest,
            HttpServletRequest request) {
        String cleanEmail = authRequest.getEmail() != null ? authRequest.getEmail().trim() : "";
        try {
            // 1. Validation des identifiants dans la base locale existante
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            cleanEmail,
                            authRequest.getPassword()
                    )
            );

            User localUser = userRepository.findByEmail(cleanEmail)
                    .orElseThrow(() -> new RuntimeException("Utilisateur introuvable"));

            if (localUser.getStatus() != User.Status.ACTIVE) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(createLoginErrorResponse("Compte utilisateur inactif ou désactivé."));
            }

            // 2. Création d'un challenge temporaire (Étape 2)
            AuthChallenge challenge = challengeService.createChallenge(localUser);

            // 3. Déclenchement de l'envoi du code OTP FlyAsky (valable 5 minutes)
            try {
                flyAskyAuthService.sendVerificationOtp(localUser.getEmail());
            } catch (IllegalArgumentException iae) {
                logger.warn("Refus envoi OTP FlyAsky pour {}: {}", localUser.getEmail(), iae.getMessage());
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(createLoginErrorResponse("Échec de l'envoi OTP FlyAsky : " + iae.getMessage()));
            } catch (Exception e) {
                logger.error("Erreur passerelle FlyAsky lors de l'envoi de l'OTP pour {}", localUser.getEmail(), e);
                return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                        .body(createLoginErrorResponse("Erreur passerelle FlyAsky lors de l'envoi de l'OTP : " + e.getMessage()));
            }

            String otpMessage = "Un code OTP a été envoyé à votre adresse e-mail " + localUser.getEmail();

            LoginResponse response = new LoginResponse();
            response.setSuccess(true);
            response.setChallengeRequired(true);
            response.setChallengeId(challenge.getChallengeId());
            response.setEmail(localUser.getEmail());
            response.setStep("FLYASKY_OTP");
            response.setMessage(otpMessage);

            logger.info("Étape 1 validée pour {}. Challenge 2FA créé: {}", localUser.getEmail(), challenge.getChallengeId());
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            try {
                auditLogService.record(
                        "LOGIN_FAILED",
                        "AUTHENTICATION",
                        "Échec d'authentification premier facteur pour: " + authRequest.getEmail(),
                        authRequest.getEmail(),
                        "Portail de connexion",
                        "FAILURE",
                        null,
                        "Identifiants incorrects"
                );
            } catch (Exception ignored) {}
            return ResponseEntity.badRequest().body(createLoginErrorResponse("Email ou mot de passe incorrect."));
        }
    }

    /**
     * ÉTAPE 2 & 3 : Validation du code OTP & Gestion de la session par FlyAsky
     * - Connexion avec le code OTP auprès de FlyAsky (POST /sign-in/email-otp) -> sessionToken
     * - Échange session -> JWT d'accès métier (GET /token) -> flyAskyJwt (10 min)
     * - Liaison de l'identité FlyAsky avec le compte local
     * - Retourne le JWT FlyAsky au front pour conservation stricte en mémoire
     */
    @PostMapping("/flyasky/verify")
    public ResponseEntity<AuthResponse> verifyFlyAskyOtp(
            @Valid @RequestBody FlyAskyVerifyRequest verifyRequest,
            HttpServletRequest request,
            HttpServletResponse response) {
        try {
            // 1. Vérification du challenge temporaire
            AuthChallenge challenge = challengeService.getValidChallenge(verifyRequest.getChallengeId())
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Challenge expiré ou invalide. Veuillez recommencer la connexion."));

            if (!StringUtils.hasText(verifyRequest.getOtp())) {
                return ResponseEntity.badRequest().body(createErrorResponse("Le code OTP FlyAsky est obligatoire."));
            }

            String sessionToken;
            try {
                // 1. Validation de l'OTP auprès de FlyAsky -> Obtention du jeton de session
                sessionToken = flyAskyAuthService.signInWithEmailOtp(challenge.getEmail(), verifyRequest.getOtp().trim());
            } catch (Exception ex) {
                logger.warn("Code OTP rejeté par FlyAsky pour {}: {}", challenge.getEmail(), ex.getMessage());
                return ResponseEntity.badRequest().body(createErrorResponse("Code OTP FlyAsky invalide ou expiré : " + ex.getMessage()));
            }

            // 2. Obtenir le JWT via GET /token ET vérification cryptographique immédiate par JWKS
            // (Pour avoir le token ou le renouveler, on fait TOUJOURS /token)
            String flyAskyJwt;
            try {
                flyAskyJwt = flyAskyAuthService.exchangeSessionForJwt(sessionToken);
            } catch (SecurityException se) {
                logger.error("ALERTE SÉCURITÉ : Authenticité du JWT FlyAsky rejetée après GET /token : {}", se.getMessage());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(createErrorResponse("Rejet de sécurité : Le JWT obtenu auprès de FlyAsky a échoué à la vérification d'authenticité (JWKS) : " + se.getMessage()));
            } catch (Exception ex) {
                logger.error("Erreur lors de l'obtention du token FlyAsky via GET /token : {}", ex.getMessage());
                return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                        .body(createErrorResponse("Échec d'obtention du token via GET /token : " + ex.getMessage()));
            }

            // 3. Décodage et validation finale des claims du JWT officiel
            FlyAskyClaims claims;
            try {
                claims = flyAskyAuthService.parseAndVerifyJwt(flyAskyJwt);
            } catch (SecurityException se) {
                logger.error("ALERTE SÉCURITÉ : Authenticité du JWT FlyAsky rejetée : {}", se.getMessage());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(createErrorResponse("Rejet de sécurité : L'authenticité du JWT n'a pas pu être validée (" + se.getMessage() + ")"));
            } catch (Exception ex) {
                logger.error("JWT FlyAsky invalide ou expiré : {}", ex.getMessage());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(createErrorResponse("Token FlyAsky invalide ou expiré : " + ex.getMessage()));
            }

            // 3. Récupération du compte local et liaison
            User localUser = userRepository.findById(challenge.getUserId())
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Compte local introuvable"));

            if (localUser.getStatus() != User.Status.ACTIVE) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(createErrorResponse("Compte utilisateur inactif."));
            }
            // Sauvegarder l'identifiant FlyAsky (sub) dans l'utilisateur local si pas encore fait
            if (localUser.getFlyAskySub() == null || !localUser.getFlyAskySub().equals(claims.getSub())) {
                localUser.setFlyAskySub(claims.getSub());
                userRepository.save(localUser);
            }

            challengeService.consumeChallenge(challenge.getChallengeId());
            userService.updateLastLogin(localUser.getEmail());

            // 4. Injecter les cookies HttpOnly sécurisés :
            // - authCookie : JWT FlyAsky (10 min)
            // - sessionCookie : jeton de session auth-session.session_token pour les échanges FlyAsky
            long maxAgeSeconds = 10 * 60; // 10 minutes selon la spécification FlyAsky
            ResponseCookie authCookie = createAuthCookie(flyAskyJwt, request, maxAgeSeconds);
            response.addHeader(HttpHeaders.SET_COOKIE, authCookie.toString());

            ResponseCookie sessionCookie = createSessionCookie(sessionToken, request, 7 * 24 * 3600);
            response.addHeader(HttpHeaders.SET_COOKIE, sessionCookie.toString());

            String jti = claims.getSid() != null ? claims.getSid() : claims.getSub();
            if (jti != null) {
                sessionRevocationService.registerSessionActivity(jti);
            }

            // Audit log
            try {
                auditLogService.record(
                        "USER_LOGIN_FLYASKY_2FA",
                        "AUTHENTICATION",
                        "Connexion réussie avec double facteur FlyAsky pour: " + localUser.getEmail(),
                        localUser.getEmail(),
                        "Session",
                        "SUCCESS",
                        request.getRemoteAddr(),
                        "Rôle local appliqué: " + localUser.getRole().name() + " | Sub FlyAsky: " + claims.getSub()
                );
            } catch (Exception ignored) {}

            // 5. Réponse : SEUL LE RÔLE DE L'UTILISATEUR DANS LA BASE LOCALE EST RETOURNÉ
            UserDto userDto = new UserDto(localUser);
            AuthResponse authResponse = new AuthResponse();
            authResponse.setSuccess(true);
            authResponse.setMessage("Authentification réussie via la session FlyAsky.");
            authResponse.setUser(userDto);
            authResponse.setToken(flyAskyJwt);              // JWT FlyAsky (10 min) en mémoire
            authResponse.setSessionToken(sessionToken);      // Jeton de session FlyAsky

            return ResponseEntity.ok(authResponse);

        } catch (ResponseStatusException rse) {
            return ResponseEntity.status(rse.getStatusCode()).body(createErrorResponse(rse.getReason()));
        } catch (Exception ex) {
            logger.error("Erreur lors de la vérification FlyAsky", ex);
            return ResponseEntity.badRequest().body(createErrorResponse("Échec de la validation: " + ex.getMessage()));
        }
    }

    /**
     * Renvoyer un nouveau code OTP FlyAsky
     */
    @PostMapping("/flyasky/resend-otp")
    public ResponseEntity<?> resendFlyAskyOtp(@RequestBody Map<String, String> body) {
        String challengeId = body.get("challengeId");
        AuthChallenge challenge = challengeService.getValidChallenge(challengeId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Challenge introuvable ou expiré."));

        try {
            flyAskyAuthService.sendVerificationOtp(challenge.getEmail());
            return ResponseEntity.ok(Map.of("success", true, "message", "Nouveau code OTP envoyé à " + challenge.getEmail()));
        } catch (IllegalArgumentException iae) {
            logger.warn("Échec renvoi OTP FlyAsky: {}", iae.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("success", false, "error", iae.getMessage()));
        } catch (Exception e) {
            logger.error("Erreur passerelle lors du renvoi de l'OTP FlyAsky: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                    .body(Map.of("success", false, "error", "Erreur passerelle FlyAsky lors du renvoi: " + e.getMessage()));
        }
    }

    /**
     * Renouvellement du JWT FlyAsky (Cycle du JWT - §5 du document).
     * Quand le JWT expire dans moins d'une minute ou sur 401, le front sollicite ce point de terminaison.
     * Le renouvellement s'effectue TOUJOURS via GET /token auprès de FlyAsky (GET /get-session servant uniquement à consulter la session).
     */
    @RequestMapping(value = {"/flyasky/refresh-token", "/flyasky/token"}, method = {RequestMethod.POST, RequestMethod.GET})
    public ResponseEntity<?> refreshFlyAskyJwt(
            @RequestBody(required = false) Map<String, String> body,
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) {

        String sessionToken = extractSessionTokenFromRequest(request, body);
        if (!StringUtils.hasText(sessionToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Jeton de session FlyAsky introuvable. Veuillez vous reconnecter."));
        }

        try {
            // Renouvellement du token : on effectue TOUJOURS GET /token auprès de FlyAsky
            String newJwt = flyAskyAuthService.exchangeSessionForJwt(sessionToken);
            FlyAskyClaims claims = flyAskyAuthService.parseAndVerifyJwt(newJwt);

            long maxAgeSeconds = 10 * 60;
            ResponseCookie authCookie = createAuthCookie(newJwt, request, maxAgeSeconds);
            response.addHeader(HttpHeaders.SET_COOKIE, authCookie.toString());

            logger.info("JWT FlyAsky renouvelé avec succès via GET /token pour {}", claims.getEmail());
            return ResponseEntity.ok(Map.of("success", true, "token", newJwt));
        } catch (SecurityException se) {
            logger.error("ALERTE SÉCURITÉ : Authenticité du JWT rejetée lors du renouvellement (GET /token): {}", se.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Rejet de sécurité : Le JWT renouvelé n'est pas authentique (" + se.getMessage() + ")"));
        } catch (Exception e) {
            logger.error("Session FlyAsky inactive ou expirée lors de GET /token: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Session FlyAsky expirée ou révoquée. Veuillez vous reconnecter."));
        }
    }

    /**
     * Consultation directe de la session courante FlyAsky (GET /get-session permet juste de consulter la session).
     */
    @GetMapping("/flyasky/session")
    public ResponseEntity<?> getFlyAskyCurrentSession(
            HttpServletRequest request) {
        String sessionToken = extractSessionTokenFromRequest(request, null);
        if (!StringUtils.hasText(sessionToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Jeton de session introuvable"));
        }
        try {
            FlyAskyAuthService.FlyAskySessionConsultation consultation = flyAskyAuthService.getSession(sessionToken);
            return ResponseEntity.ok(Map.of(
                    "session", consultation.session(),
                    "user", consultation.user()
            ));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Session FlyAsky inactive ou expirée: " + e.getMessage()));
        }
    }

    /**
     * Déconnexion (POST /sign-out sur FlyAsky, destruction de la session et révocation)
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            @RequestBody(required = false) Map<String, String> body,
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) {

        String sessionToken = extractSessionTokenFromRequest(request, body);
        if (StringUtils.hasText(sessionToken)) {
            flyAskyAuthService.signOut(sessionToken);
        }
        String token = extractTokenFromRequest(request);
        if (StringUtils.hasText(token)) {
            String userEmail = authentication != null ? authentication.getName() : null;
            sessionRevocationService.revokeToken(token, null, null, userEmail);
        }
        for (ResponseCookie c : clearAuthCookies(request)) {
            response.addHeader(HttpHeaders.SET_COOKIE, c.toString());
        }
        SecurityContextHolder.clearContext();
        return ResponseEntity.ok(Map.of("message", "Déconnexion et fermeture de la session FlyAsky réussies"));
    }

    /**
     * Récupérer les informations de l'utilisateur connecté avec son rôle local.
     */
    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equals(authentication.getPrincipal())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Non authentifié"));
        }

        return userService.getUserByEmail(authentication.getName())
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
    }

    @PostMapping("/validate")
    public ResponseEntity<?> validateToken(HttpServletRequest request) {
        String token = extractTokenFromRequest(request);
        if (StringUtils.hasText(token)) {
            try {
                FlyAskyClaims claims = flyAskyAuthService.parseAndVerifyJwt(token);
                if (!claims.isExpired()) {
                    return ResponseEntity.ok().build();
                }
            } catch (Exception ignored) {
                if (tokenProvider.validateToken(token)) {
                    return ResponseEntity.ok().build();
                }
            }
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Session invalide ou expirée");
    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie c : request.getCookies()) {
                if (COOKIE_NAME.equals(c.getName())
                        || "passbanned_jwt".equals(c.getName())
                        || "jwt_token".equals(c.getName())) {
                    if (StringUtils.hasText(c.getValue())) {
                        return c.getValue();
                    }
                }
            }
        }
        String authHeader = request.getHeader("Authorization");
        if (StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }

    public static String extractSessionTokenFromRequest(HttpServletRequest request, Map<String, String> body) {
        if (body != null && StringUtils.hasText(body.get("sessionToken"))) {
            return body.get("sessionToken").trim();
        }
        if (request != null && request.getCookies() != null) {
            for (Cookie c : request.getCookies()) {
                if (SESSION_COOKIE_NAME.equals(c.getName())
                        || "session_token".equals(c.getName())
                        || "auth-session".equals(c.getName())) {
                    if (StringUtils.hasText(c.getValue())) {
                        return c.getValue().trim();
                    }
                }
            }
        }
        if (request != null) {
            String header = request.getHeader("X-Session-Token");
            if (StringUtils.hasText(header)) {
                return header.trim();
            }
        }
        return null;
    }

    private AuthResponse createErrorResponse(String message) {
        AuthResponse res = new AuthResponse();
        res.setSuccess(false);
        res.setMessage(message);
        return res;
    }

    private LoginResponse createLoginErrorResponse(String message) {
        LoginResponse res = new LoginResponse();
        res.setSuccess(false);
        res.setChallengeRequired(false);
        res.setMessage(message);
        return res;
    }

    public static ResponseCookie createAuthCookie(String token, HttpServletRequest request, long maxAgeSeconds) {
        boolean isSecure = request.isSecure()
                || "https".equalsIgnoreCase(request.getHeader("X-Forwarded-Proto"))
                || (!"localhost".equalsIgnoreCase(request.getServerName()) && !"127.0.0.1".equals(request.getServerName()));

        ResponseCookie.ResponseCookieBuilder builder = ResponseCookie.from(COOKIE_NAME, token)
                .httpOnly(true)
                .path("/")
                .maxAge(maxAgeSeconds);

        if (isSecure) {
            builder.secure(true).sameSite("None");
        } else {
            builder.secure(false).sameSite("Lax");
        }

        return builder.build();
    }

    public static ResponseCookie createSessionCookie(String sessionToken, HttpServletRequest request, long maxAgeSeconds) {
        boolean isSecure = request.isSecure()
                || "https".equalsIgnoreCase(request.getHeader("X-Forwarded-Proto"))
                || (!"localhost".equalsIgnoreCase(request.getServerName()) && !"127.0.0.1".equals(request.getServerName()));

        ResponseCookie.ResponseCookieBuilder builder = ResponseCookie.from(SESSION_COOKIE_NAME, sessionToken)
                .httpOnly(true)
                .path("/")
                .maxAge(maxAgeSeconds);

        if (isSecure) {
            builder.secure(true).sameSite("None");
        } else {
            builder.secure(false).sameSite("Lax");
        }

        return builder.build();
    }

    public static List<ResponseCookie> clearAuthCookies(HttpServletRequest request) {
        boolean isSecure = request.isSecure()
                || "https".equalsIgnoreCase(request.getHeader("X-Forwarded-Proto"))
                || (!"localhost".equalsIgnoreCase(request.getServerName()) && !"127.0.0.1".equals(request.getServerName()));

        ResponseCookie newCookie = ResponseCookie.from(COOKIE_NAME, "")
                .httpOnly(true)
                .path("/")
                .maxAge(0)
                .secure(isSecure)
                .sameSite(isSecure ? "None" : "Lax")
                .build();

        ResponseCookie legacyCookie = ResponseCookie.from("passbanned_jwt", "")
                .httpOnly(true)
                .path("/")
                .maxAge(0)
                .secure(isSecure)
                .sameSite(isSecure ? "None" : "Lax")
                .build();

        ResponseCookie sessionCookie = ResponseCookie.from(SESSION_COOKIE_NAME, "")
                .httpOnly(true)
                .path("/")
                .maxAge(0)
                .secure(isSecure)
                .sameSite(isSecure ? "None" : "Lax")
                .build();

        return List.of(newCookie, legacyCookie, sessionCookie);
    }
}