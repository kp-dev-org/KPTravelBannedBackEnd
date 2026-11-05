package com.PassBanned.API.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class CreateUserRequest {

    @NotBlank
    @Size(max = 100, message = "Le nom ne doit pas dépasser 100 caractères")
    private String name;

    @Email
    @NotBlank
    @Size(max = 100, message = "L'adresse email ne doit pas dépasser 100 caractères")
    private String email;

    @NotBlank
    @Size(min = 6, max = 120, message = "Le mot de passe doit comporter entre 6 et 120 caractères")
    private String password;

    @NotNull
    @Size(max = 20)
    private String role;

    @NotNull
    @Size(max = 20)
    private String status;

    @Size(max = 255, message = "L'URL de l'avatar ne doit pas dépasser 255 caractères")
    private String avatarUrl;

    private boolean mfaEnabled;

}
