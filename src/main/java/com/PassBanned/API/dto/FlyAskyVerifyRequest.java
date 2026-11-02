package com.PassBanned.API.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class FlyAskyVerifyRequest {
    @NotBlank(message = "L'identifiant de challenge est obligatoire")
    private String challengeId;
    private String email;
    private String otp;
    private String flyAskyJwt;
}
