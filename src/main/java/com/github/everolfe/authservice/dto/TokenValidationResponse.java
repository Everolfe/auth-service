package com.github.everolfe.authservice.dto;


import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@RequiredArgsConstructor
@Getter
@Setter
public class TokenValidationResponse {

    private boolean valid;
    private String userId;
    private String role;
    private String message;

    public static TokenValidationResponse valid(String userId, String role, String message) {
        return new TokenValidationResponse(true, userId, role, message);
    }

    public static TokenValidationResponse invalid(String message) {
        return new TokenValidationResponse(false, null, null, message);
    }
}
