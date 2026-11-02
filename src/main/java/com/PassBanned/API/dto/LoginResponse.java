package com.PassBanned.API.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class LoginResponse {
    private boolean success = true;
    private boolean challengeRequired = false;
    private String challengeId;
    private String step; // "FLYASKY_OTP", "COMPLETED"
    private String message;
    private String email;
}
