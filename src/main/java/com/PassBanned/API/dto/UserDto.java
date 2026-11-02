package com.PassBanned.API.dto;


import com.PassBanned.API.Model.User;
import jakarta.persistence.Column;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.time.LocalDateTime;

@Setter
@Getter
@ToString
public class UserDto {
    // Getters and Setters
    private Long id;

    @NotBlank
    @Size(max = 100)
    private String name;

    @NotBlank
    @Email
    @Size(max = 100)
    private String email;

    private User.Role role;
    private User.Status status;
    private String avatarUrl;
    private LocalDateTime lastLogin;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private boolean mfaEnabled ;
    private boolean mfaConfigured;
    private String mfaSecret;

    // Constructors
    public UserDto() {}

    public UserDto(User user) {
        if (user != null) {
            this.name = user.getName();
            this.email = user.getEmail();
            this.role = user.getRole();
            this.status = user.getStatus();
            this.avatarUrl = user.getAvatarUrl();
            this.lastLogin = user.getLastLogin();
            this.createdAt = user.getCreatedAt();
            this.updatedAt = user.getUpdatedAt();
            this.mfaEnabled = user.isMfaEnabled();
            this.mfaConfigured = user.isMfaConfigured();
            this.mfaSecret = user.getMfaSecret();
        }
    }

}