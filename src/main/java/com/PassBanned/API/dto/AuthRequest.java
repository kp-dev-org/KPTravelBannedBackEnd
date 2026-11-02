package com.PassBanned.API.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@NoArgsConstructor
@AllArgsConstructor
@ToString(exclude = "password")
public class AuthRequest {
    @NotBlank
    @Email
    private String email;

    @NotBlank
    private String password;

    private Integer mfaCode;
}