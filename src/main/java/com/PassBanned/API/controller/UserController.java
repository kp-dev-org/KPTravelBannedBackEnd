package com.PassBanned.API.controller;

import com.PassBanned.API.Model.User;
import com.PassBanned.API.dto.CreateUserRequest;
import com.PassBanned.API.dto.PasswordChangeRequest;
import com.PassBanned.API.dto.UpdateUserRequest;
import com.PassBanned.API.dto.UserDto;
import com.PassBanned.API.repository.UserRepository;
import com.PassBanned.API.service.LocalFileStorageService;
import com.PassBanned.API.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

@RestController
@RequestMapping("/users")
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private LocalFileStorageService fileStorageService;

    private User getCurrentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return null;
        }
        return userRepository.findByEmail(auth.getName()).orElse(null);
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<List<UserDto>> getAllUsers() {
        List<UserDto> users = userService.getAllUsers();
        return ResponseEntity.ok(users);
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<UserDto> getUserById(@PathVariable Long id) {
        return userService.getUserById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<?> createUser(@Valid @RequestBody CreateUserRequest request) {
        try {
            User currentUser = getCurrentUser();
            boolean isSuperAdmin = currentUser != null && currentUser.getRole() == User.Role.SUPER_ADMIN;
            User.Role requestedRole = User.Role.valueOf(request.getRole().toUpperCase());

            // Un administrateur ne peut pas créer un ADMIN ou SUPER_ADMIN
            if (!isSuperAdmin && requestedRole != User.Role.USER) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                    "error", "Accès refusé",
                    "message", "Un administrateur ne peut pas créer un compte Administrateur ou Super-Administrateur. Seul le Super-Admin a ce privilège."
                ));
            }

            UserDto userDto = new UserDto();
            userDto.setName(request.getName());
            userDto.setEmail(request.getEmail());
            userDto.setRole(requestedRole);
            userDto.setStatus(User.Status.valueOf(request.getStatus().toUpperCase()));
            userDto.setAvatarUrl(request.getAvatarUrl());
            userDto.setMfaEnabled(request.isMfaEnabled());
            String password = request.getPassword();
            UserDto createdUser = userService.createUser(userDto, password);
            return ResponseEntity.status(HttpStatus.CREATED).body(createdUser);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("message", "Rôle ou statut invalide: " + e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage() != null ? e.getMessage() : "Erreur lors de la création"));
        }
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<?> updateUser(@PathVariable Long id, @Valid @RequestBody UpdateUserRequest request) {
        try {
            User currentUser = getCurrentUser();
            boolean isSuperAdmin = currentUser != null && currentUser.getRole() == User.Role.SUPER_ADMIN;

            Optional<User> targetOpt = userRepository.findById(id);
            if (targetOpt.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("message", "Utilisateur non trouvé"));
            }
            User target = targetOpt.get();

            // Règle formelle : un admin ne doit pas avoir la possibilité de modifier le compte d'un admin ou super-admin
            if (!isSuperAdmin && (target.getRole() == User.Role.ADMIN || target.getRole() == User.Role.SUPER_ADMIN)) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                    "error", "Accès refusé",
                    "message", "Un administrateur ne peut pas modifier le compte d'un Administrateur ou d'un Super-Administrateur."
                ));
            }

            User.Role newRole = User.Role.valueOf(request.getRole().toUpperCase());
            // Un admin ne peut pas promouvoir un compte en ADMIN ou SUPER_ADMIN
            if (!isSuperAdmin && newRole != User.Role.USER) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                    "error", "Accès refusé",
                    "message", "Un administrateur ne peut pas promouvoir un compte en Administrateur ou Super-Administrateur."
                ));
            }

            UserDto userDto = new UserDto();
            userDto.setName(request.getName());
            userDto.setEmail(request.getEmail());
            userDto.setRole(newRole);
            userDto.setStatus(User.Status.valueOf(request.getStatus().toUpperCase()));
            userDto.setAvatarUrl(request.getAvatarurl());
            userDto.setMfaEnabled(request.isMfaEnabled());
            UserDto updatedUser = userService.updateUser(id, userDto, request.getPassword());
            return ResponseEntity.ok(updatedUser);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("message", "Rôle ou statut invalide: " + e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage() != null ? e.getMessage() : "Erreur de mise à jour"));
        }
    }

    @PostMapping("/{id}/avatar")
    public ResponseEntity<Map<String, String>> uploadAvatar(
            @PathVariable Long id, 
            @RequestParam("avatar") MultipartFile file,
            HttpServletRequest request) {
        try {
            if (file.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Fichier vide"));
            }

            if (!Objects.requireNonNull(file.getContentType()).startsWith("image/")) {
                return ResponseEntity.badRequest().body(Map.of("error", "Le fichier doit être une image"));
            }

            if (file.getSize() > 5 * 1024 * 1024) { // 5MB
                return ResponseEntity.badRequest().body(Map.of("error", "Le fichier ne doit pas dépasser 5MB"));
            }

            User currentUser = getCurrentUser();
            boolean isSuperAdmin = currentUser != null && currentUser.getRole() == User.Role.SUPER_ADMIN;

            Optional<User> targetOpt = userRepository.findById(id);
            if (targetOpt.isEmpty()) {
                return ResponseEntity.notFound().build();
            }
            User target = targetOpt.get();

            // Un admin ne peut pas modifier l'avatar d'un autre admin ou super-admin
            if (!isSuperAdmin && !target.getEmail().equals(currentUser != null ? currentUser.getEmail() : null)) {
                if (target.getRole() == User.Role.ADMIN || target.getRole() == User.Role.SUPER_ADMIN) {
                    return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                        "error", "Accès refusé",
                        "message", "Un administrateur ne peut pas modifier le profil d'un Administrateur ou Super-Administrateur."
                    ));
                }
            }

            UserDto user = userService.getUserById(id)
                    .orElseThrow(() -> new RuntimeException("Utilisateur non trouvé"));

            String avatarUrl = fileStorageService.storeFile(file, request);
            user.setAvatarUrl(avatarUrl);
            userService.updateUser(id, user, null);

            return ResponseEntity.ok(Map.of("avatarUrl", avatarUrl, "url", avatarUrl));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Erreur lors de l'upload: " + e.getMessage()));
        }
    }

    @PostMapping("/avatar/upload")
    public ResponseEntity<Map<String, String>> uploadAvatarForNewUser(
            @RequestParam("avatar") MultipartFile file,
            HttpServletRequest request) {
        try {
            if (file.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Fichier vide"));
            }

            if (!Objects.requireNonNull(file.getContentType()).startsWith("image/")) {
                return ResponseEntity.badRequest().body(Map.of("error", "Le fichier doit être une image"));
            }

            if (file.getSize() > 5 * 1024 * 1024) { // 5MB
                return ResponseEntity.badRequest().body(Map.of("error", "Le fichier ne doit pas dépasser 5MB"));
            }
            String avatarUrl = fileStorageService.storeFile(file, request);

            return ResponseEntity.ok(Map.of("avatarUrl", avatarUrl, "url", avatarUrl));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Erreur lors de l'upload: " + e.getMessage()));
        }
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        try {
            User currentUser = getCurrentUser();
            boolean isSuperAdmin = currentUser != null && currentUser.getRole() == User.Role.SUPER_ADMIN;

            Optional<User> targetOpt = userRepository.findById(id);
            if (targetOpt.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("message", "Utilisateur non trouvé"));
            }
            User target = targetOpt.get();

            // Règle formelle : un admin ne doit pas avoir la possibilité de supprimer le compte d'un admin ou super-admin
            if (!isSuperAdmin && (target.getRole() == User.Role.ADMIN || target.getRole() == User.Role.SUPER_ADMIN)) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                    "error", "Accès refusé",
                    "message", "Un administrateur ne peut pas supprimer le compte d'un Administrateur ou d'un Super-Administrateur."
                ));
            }

            if (currentUser != null && currentUser.getId().equals(id)) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                    "error", "Action non autorisée",
                    "message", "Vous ne pouvez pas supprimer votre propre compte actif."
                ));
            }

            userService.deleteUser(id);
            return ResponseEntity.ok(Map.of("status", "ok", "message", "Utilisateur supprimé avec succès"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage() != null ? e.getMessage() : "Erreur de suppression"));
        }
    }

    @GetMapping("/stats")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<Map<String, Long>> getUserStats() {
        Map<String, Long> stats = Map.of(
            "totalUsers", userService.getTotalUsers(),
            "adminCount", userService.getAdminCount(),
            "superAdminCount", userService.getSuperAdminCount(),
            "activeUsers", userService.getActiveUserCount()
        );
        return ResponseEntity.ok(stats);
    }

    @PostMapping("/{id}/password")
    public ResponseEntity<?> changePassword(
            @PathVariable Long id,
            @Valid @RequestBody PasswordChangeRequest request) {
        try {
            userService.changePassword(id, request.getAvatarUrl(), request.getCurrentPassword(), request.getNewPassword());
            return ResponseEntity.ok(Map.of("message", "Password changed successfully"));
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("message", e.getMessage()));
        }
    }

    @PostMapping("/{id}/enable-mfa")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<?> enableMfa(@PathVariable Long id) {
        User currentUser = getCurrentUser();
        boolean isSuperAdmin = currentUser != null && currentUser.getRole() == User.Role.SUPER_ADMIN;

        Optional<User> targetOpt = userRepository.findById(id);
        if (targetOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("message", "Utilisateur non trouvé"));
        }
        User target = targetOpt.get();

        if (!isSuperAdmin && (target.getRole() == User.Role.ADMIN || target.getRole() == User.Role.SUPER_ADMIN)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                "error", "Accès refusé",
                "message", "Un administrateur ne peut pas modifier la sécurité MFA d'un Administrateur ou Super-Administrateur."
            ));
        }

        String url = userService.enableMfa(id);
        return ResponseEntity.ok(Map.of("otpAuthUrl", url));
    }

    @PostMapping("/{id}/disable-mfa")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<?> disableMfa(@PathVariable Long id) {
        User currentUser = getCurrentUser();
        boolean isSuperAdmin = currentUser != null && currentUser.getRole() == User.Role.SUPER_ADMIN;

        Optional<User> targetOpt = userRepository.findById(id);
        if (targetOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("message", "Utilisateur non trouvé"));
        }
        User target = targetOpt.get();

        if (!isSuperAdmin && (target.getRole() == User.Role.ADMIN || target.getRole() == User.Role.SUPER_ADMIN)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                "error", "Accès refusé",
                "message", "Un administrateur ne peut pas modifier la sécurité MFA d'un Administrateur ou Super-Administrateur."
            ));
        }

        userService.disableMfa(id);
        return ResponseEntity.ok(Map.of("status", "ok"));
    }

    @PostMapping("/{id}/reset-mfa")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<?> resetMFA(@PathVariable Long id) {
        User currentUser = getCurrentUser();
        boolean isSuperAdmin = currentUser != null && currentUser.getRole() == User.Role.SUPER_ADMIN;

        Optional<User> targetOpt = userRepository.findById(id);
        if (targetOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("message", "Utilisateur non trouvé"));
        }
        User target = targetOpt.get();

        if (!isSuperAdmin && (target.getRole() == User.Role.ADMIN || target.getRole() == User.Role.SUPER_ADMIN)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                "error", "Accès refusé",
                "message", "Un administrateur ne peut pas réinitialiser le MFA d'un Administrateur ou Super-Administrateur."
            ));
        }

        userService.resetMfa(id);
        return ResponseEntity.ok(Map.of("status", "ok"));
    }
}