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

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> authenticateUser(
            @Valid @RequestBody AuthRequest authRequest,
            HttpServletRequest request) {
        String cleanEmail = authRequest.getEmail() != null ? authRequest.getEmail().trim().toLowerCase() : "";
        try {
            Optional<User> existingUserOpt = userRepository.findByEmail(cleanEmail);
            if (existingUserOpt.isPresent() && existingUserOpt.get().getStatus() != User.Status.ACTIVE) {
                try {
                    auditLogService.record(
                            "LOGIN_BLOCKED_INACTIVE",
                            "AUTHENTICATION",
                            "Tentative de connexion sur un compte désactivé: " + cleanEmail,
                            cleanEmail,
                            "Portail de connexion",
                            "WARNING",
                            request.getRemoteAddr(),
                            "Compte désactivé"
                    );
                } catch (Exception ignored) {}
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(createLoginErrorResponse("Your account is blocked. Please contact the administrator."));
            }
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            cleanEmail,
                            authRequest.getPassword()
                    )
            );

            User localUser = userRepository.findByEmail(cleanEmail)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            if (localUser.getStatus() != User.Status.ACTIVE) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(createLoginErrorResponse("Your account is blocked. Please contact the administrator"));
            }

            AuthChallenge challenge = challengeService.createChallenge(localUser);
            try {
                flyAskyAuthService.sendVerificationOtp(localUser.getEmail());
            } catch (IllegalArgumentException iae) {
                logger.warn("OTP sending refused for {}: {}", localUser.getEmail(), iae.getMessage());
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(createLoginErrorResponse("Failed to send OTP  : " + iae.getMessage()));
            } catch (Exception e) {
                logger.error("Erreur passerelle FlyAsky lors de l'envoi de l'OTP pour {}", localUser.getEmail(), e);
                return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                        .body(createLoginErrorResponse("Erreur passerelle FlyAsky lors de l'envoi de l'OTP : " + e.getMessage()));
            }

            String otpMessage = "An OTP code has been sent to your email address" + localUser.getEmail();

            LoginResponse response = new LoginResponse();
            response.setSuccess(true);
            response.setChallengeRequired(true);
            response.setChallengeId(challenge.getChallengeId());
            response.setEmail(localUser.getEmail());
            response.setStep("FLYASKY_OTP");
            response.setMessage(otpMessage);

            logger.info("Étape 1 validée pour {}. Challenge 2FA créé: {}", localUser.getEmail(), challenge.getChallengeId());
            return ResponseEntity.ok(response);

        } catch (org.springframework.security.authentication.DisabledException | org.springframework.security.authentication.LockedException de) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(createLoginErrorResponse("Votre compte est désactivé. Veuillez contacter l'administrateur."));
        } catch (Exception e) {
            // Vérifier si la raison de l'échec est un compte désactivé
            Optional<User> checkInactive = userRepository.findByEmail(cleanEmail);
            if (checkInactive.isPresent() && checkInactive.get().getStatus() != User.Status.ACTIVE) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(createLoginErrorResponse("Votre compte est désactivé. Veuillez contacter l'administrateur."));
            }
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

    @PostMapping("/flyasky/verify")
    public ResponseEntity<AuthResponse> verifyFlyAskyOtp(
            @Valid @RequestBody FlyAskyVerifyRequest verifyRequest,
            HttpServletRequest request,
            HttpServletResponse response) {
        try {
            AuthChallenge challenge = challengeService.getValidChallenge(verifyRequest.getChallengeId())
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Challenge expired or invalid. Please restart the login process."));

            if (!StringUtils.hasText(verifyRequest.getOtp())) {
                return ResponseEntity.badRequest().body(createErrorResponse("OTP code is mandatory."));
            }

            String sessionToken;
            try {
                sessionToken = flyAskyAuthService.signInWithEmailOtp(challenge.getEmail(), verifyRequest.getOtp().trim());
            } catch (Exception ex) {
                logger.warn("OTP code rejected for {}: {}", challenge.getEmail(), ex.getMessage());
                return ResponseEntity.badRequest().body(createErrorResponse("OTP code invalid or expired : " + ex.getMessage()));
            }

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
                        .body(createErrorResponse("Your account is disabled. Please contact the administrator."));
            }

            // Sauvegarder l'identifiant FlyAsky (sub) dans l'utilisateur local si pas encore fait
            if (localUser.getFlyAskySub() == null || !localUser.getFlyAskySub().equals(claims.getSub())) {
                localUser.setFlyAskySub(claims.getSub());
                userRepository.save(localUser);
            }

            challengeService.consumeChallenge(challenge.getChallengeId());
            userService.updateLastLogin(localUser.getEmail());
            long maxAgeSeconds = 10 * 60; // 10 minutes selon la spécification FlyAsky
            ResponseCookie authCookie = createAuthCookie(flyAskyJwt, request, maxAgeSeconds);
            response.addHeader(HttpHeaders.SET_COOKIE, authCookie.toString());
            ResponseCookie sessionCookie = createSessionCookie(sessionToken, request, 7 * 24 * 3600);
            response.addHeader(HttpHeaders.SET_COOKIE, sessionCookie.toString());
            String jti = claims.getSid() != null ? claims.getSid() : claims.getSub();
            if (jti != null) {
                sessionRevocationService.registerSessionActivity(jti, localUser.getEmail());
            }
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
            UserDto userDto = new UserDto(localUser);
            AuthResponse authResponse = new AuthResponse();
            authResponse.setSuccess(true);
            authResponse.setMessage("Authentification réussie via la session FlyAsky.");
            authResponse.setUser(userDto);
            return ResponseEntity.ok(authResponse);

        } catch (ResponseStatusException rse) {
            return ResponseEntity.status(rse.getStatusCode()).body(createErrorResponse(rse.getReason()));
        } catch (Exception ex) {
            logger.error("Erreur lors de la vérification FlyAsky", ex);
            return ResponseEntity.badRequest().body(createErrorResponse("Validation failed: " + ex.getMessage()));
        }
    }

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
            String jti = claims.getSid() != null ? claims.getSid() : claims.getSub();

            // SÉCURITÉ : Bloquer le renouvellement si la session est inactive (> 20 min) ou révoquée
            if (sessionRevocationService.isRevoked(newJwt, jti, claims.getIssuedAt(), claims.getEmail())
                    || sessionRevocationService.isUserInactive(claims.getEmail(), jti)) {
                logger.warn("Refus de renouvellement de token : session inactive (> 20 min) ou révoquée pour {}", claims.getEmail());
                sessionRevocationService.revokeSessionDueToInactivity(claims.getEmail(), newJwt, jti);
                for (ResponseCookie c : clearAuthCookies(request)) {
                    response.addHeader(HttpHeaders.SET_COOKIE, c.toString());
                }
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Session expirée pour cause d'inactivité. Veuillez vous reconnecter."));
            }

            // Mettre à jour l'horodatage d'activité
            sessionRevocationService.registerSessionActivity(jti, claims.getEmail());
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

    @PostMapping("/expire-session")
    public ResponseEntity<?> expireSession(
            @RequestBody(required = false) Map<String, String> body,
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) {

        String userEmail = authentication != null ? authentication.getName() : null;
        if (body != null && StringUtils.hasText(body.get("email"))) {
            userEmail = body.get("email");
        }

        String sessionToken = extractSessionTokenFromRequest(request, body);
        if (StringUtils.hasText(sessionToken)) {
            try {
                flyAskyAuthService.signOut(sessionToken);
            } catch (Exception ignored) {}
        }

        String token = extractTokenFromRequest(request);
        if (userEmail != null) {
            sessionRevocationService.revokeSessionDueToInactivity(userEmail, token, null);
        }

        for (ResponseCookie c : clearAuthCookies(request)) {
            response.addHeader(HttpHeaders.SET_COOKIE, c.toString());
        }

        SecurityContextHolder.clearContext();
        logger.warn("Session expirée pour inactivité (20 min) et cookies invalidés pour {}", userEmail);
        return ResponseEntity.ok(Map.of("message", "Session expirée pour inactivité et invalidée"));
    }

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

        if (isSecure) {builder.secure(true).sameSite("None");} else {builder.secure(false).sameSite("Lax");}

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