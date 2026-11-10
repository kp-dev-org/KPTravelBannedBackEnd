package com.PassBanned.API.dto;

import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class PasswordChangeRequest {
    private String email;
    private String avatarUrl;
    private String name;
    private String currentPassword;
    @Size(min = 6, message = "Password must be at least 6 characters")
    private String newPassword;
    public PasswordChangeRequest() {}
}