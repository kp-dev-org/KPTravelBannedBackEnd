package com.PassBanned.API.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class AuthResponse {
    private boolean success = true;
    private String message;
    private UserDto user;
    private String token;
    private String sessionToken;
    private String type = "Bearer";
    public AuthResponse(String token, UserDto user) {
        this.token = token;
        this.user = user;
    }
}