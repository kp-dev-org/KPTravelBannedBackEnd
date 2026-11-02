package com.PassBanned.API.service;


import com.PassBanned.API.Model.User;
import com.PassBanned.API.config.SecurityConfig;
import com.PassBanned.API.dto.UserDto;
import com.PassBanned.API.repository.UserRepository;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@Transactional
public class UserService implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuditLogService auditLogService;




    private final GoogleAuthenticator gAuth = new GoogleAuthenticator();

    public String enableMfa(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        GoogleAuthenticatorKey key = gAuth.createCredentials();
        user.setMfaSecret(key.getKey());
        user.setMfaEnabled(true);
        userRepository.save(user);

        String otpAuthURL;

        otpAuthURL = String.format("otpauth://totp/PassBanned:%s?secret=%s&issuer=PassBanned", user.getEmail(), key.getKey()
        );
        return otpAuthURL;
    }

    public void disableMfa(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        user.setMfaEnabled(false);
        user.setMfaConfigured(false);
        user.setMfaSecret(null);
        userRepository.save(user);
    }

    public void resetMfa(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));
        GoogleAuthenticatorKey key = gAuth.createCredentials();
        user.setMfaSecret(key.getKey());
        user.setMfaConfigured(false);
        userRepository.save(user);
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));
        // On retourne un objet UserDetails que Spring Security peut utiliser pour l'authentification
        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getEmail())
                .password(user.getPassword())
                .authorities("ROLE_" + user.getRole().name())
                .accountExpired(false)
                .accountLocked(user.getStatus() == User.Status.INACTIVE)
                .credentialsExpired(false)
                .disabled(user.getStatus() == User.Status.INACTIVE)
                .build();
    }

    public List<UserDto> getAllUsers() {
        return userRepository.findAll().stream()
                .map(this::convertToDto)
                .collect(Collectors.toList());
    }

    public Optional<UserDto> getUserById(Long id) {
        return userRepository.findById(id)
                .map(this::convertToDto);
    }

    public Optional<UserDto> getUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .map(this::convertToDto);
    }

    public UserDto createUser(UserDto userDto, String password) {
        if (userRepository.existsByEmail(userDto.getEmail())) {
            throw new RuntimeException("Email already exists");
        }
        User user = new User();
        user.setName(userDto.getName());
        user.setEmail(userDto.getEmail());
        user.setPassword(passwordEncoder.encode(password));
        user.setRole(userDto.getRole() != null ? userDto.getRole() : User.Role.USER);
        user.setStatus(userDto.getStatus() != null ? userDto.getStatus() : User.Status.ACTIVE);
        user.setAvatarUrl(userDto.getAvatarUrl());
        if(userDto.isMfaEnabled()){
            String secret = gAuth.createCredentials().getKey();
            user.setMfaSecret(secret);
            user.setMfaEnabled(true);
        }
        user.setMfaConfigured(false);
        User savedUser = userRepository.save(user);

        try {
            auditLogService.record(
                "USER_CREATED",
                "USERS",
                "Création du compte utilisateur: " + savedUser.getName() + " (" + savedUser.getEmail() + ") - Rôle: " + savedUser.getRole(),
                null,
                "User #" + savedUser.getId(),
                "SUCCESS",
                null,
                "Rôle: " + savedUser.getRole() + ", Statut: " + savedUser.getStatus()
            );
        } catch (Exception ignored) {}

        return convertToDto(savedUser);
    }

    public UserDto updateUser(Long id, UserDto userDto, String password) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setName(userDto.getName());
        user.setRole(userDto.getRole());
        user.setStatus(userDto.getStatus());
        user.setAvatarUrl(userDto.getAvatarUrl());
        user.setEmail(userDto.getEmail());
        user.setMfaEnabled(userDto.isMfaEnabled());
        if(user.isMfaEnabled() && !userDto.isMfaEnabled())
        {
            user.setMfaEnabled(false);
            user.setMfaSecret("");
        } else if(!user.isMfaEnabled() && userDto.isMfaEnabled()) {
            String secret = gAuth.createCredentials().getKey();
            user.setMfaSecret(secret);
            user.setMfaConfigured(false);
        }

        if (password != null && !password.isBlank())
        {
            user.setPassword(passwordEncoder.encode(password));
        }

        User updatedUser = userRepository.save(user);

        try {
            auditLogService.record(
                "USER_UPDATED",
                "USERS",
                "Modification du compte utilisateur: " + updatedUser.getName() + " (" + updatedUser.getEmail() + ")",
                null,
                "User #" + id,
                "SUCCESS",
                null,
                "Rôle: " + updatedUser.getRole() + ", Statut: " + updatedUser.getStatus()
            );
        } catch (Exception ignored) {}

        return convertToDto(updatedUser);
    }

    public void deleteUser(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));
        userRepository.deleteById(id);

        try {
            auditLogService.record(
                "USER_DELETED",
                "USERS",
                "Suppression du compte utilisateur: " + user.getName() + " (" + user.getEmail() + ")",
                null,
                "User #" + id,
                "WARNING",
                null,
                "Rôle: " + user.getRole()
            );
        } catch (Exception ignored) {}
    }

    public void updateLastLogin(String email) {
        userRepository.findByEmail(email).ifPresent(user -> {
            user.setLastLogin(LocalDateTime.now());
            userRepository.save(user);
        });
    }

    public long getTotalUsers() {
        return userRepository.count();
    }

    public long getAdminCount() {
        return userRepository.countAdmins();
    }

    public long getActiveUserCount() {
        return userRepository.countActiveUsers();
    }
    public void changePassword(Long id,String avatarUrl, String currentPassword, String newPassword) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
            throw new RuntimeException("Current password is incorrect");
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        user.setAvatarUrl(avatarUrl);
        userRepository.save(user);
    }

    private UserDto convertToDto(User user) {
        UserDto dto = new UserDto();
        dto.setId(user.getId());
        dto.setName(user.getName());
        dto.setEmail(user.getEmail());
        dto.setRole(user.getRole());
        dto.setStatus(user.getStatus());
        dto.setAvatarUrl(user.getAvatarUrl());
        dto.setLastLogin(user.getLastLogin());
        dto.setCreatedAt(user.getCreatedAt());
        dto.setUpdatedAt(user.getUpdatedAt());
        dto.setMfaEnabled(user.isMfaEnabled());
        dto.setMfaSecret(user.getMfaSecret());
        dto.setMfaConfigured(user.isMfaConfigured());
        return dto;
    }


}
