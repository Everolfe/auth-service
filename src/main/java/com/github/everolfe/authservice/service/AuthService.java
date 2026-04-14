package com.github.everolfe.authservice.service;

import com.github.everolfe.authservice.dto.GetRefreshTokenDto;
import com.github.everolfe.authservice.dto.GetRegistrationStatusDto;
import com.github.everolfe.authservice.dto.TokenValidationResponse;
import com.github.everolfe.authservice.dto.auth.CreateAuthDto;
import com.github.everolfe.authservice.dto.auth.GetAuthDto;
import com.github.everolfe.authservice.dto.auth.LoginDto;
import java.util.Map;
import java.util.UUID;

/**
 * Service interface for authentication operations.
 * Provides core authentication functionality including registration, login,
 * token management, and validation.
 */
public interface AuthService {

    /**
     * Registers a new user in the system.
     *
     * @param createAuthDto the user credentials for registration
     * @return UUID of outbox event registration and async try to create user, null otherwise
     */
    UUID register(CreateAuthDto createAuthDto);

    /**
     * Authenticates a user and generates access and refresh tokens.
     *
     * @param loginDto the email and password for login
     * @return {@link GetAuthDto} containing the generated access token and refresh token
     */
    GetAuthDto login(LoginDto loginDto);

    /**
     * Generates a new access token using a valid refresh token.
     *
     * @param refreshTokenDto the DTO containing the refresh token
     * @return {@link GetAuthDto} containing the new access token and refresh token
     */
    GetAuthDto refreshToken(GetRefreshTokenDto refreshTokenDto);

    /**
     * Retrieves the JSON Web Key Set (JWKS) for token validation.
     *
     * @return a map containing the JWKS configuration
     */
    Map<String, Object> getJwtSet();

    /**
     * Logs out a user by invalidating the provided refresh token.
     *
     * @param refreshToken the refresh token to invalidate
     */
    void logout(String refreshToken);

    /**
     * Revokes all active tokens for a specific user.
     *
     * @param userSub the UUID of the user whose tokens should be revoked
     */
    void revokeAllUserTokens(UUID userSub);

    /**
     * Validates the provided JWT token and returns a structured validation result.
     *
     * @param token the token to validate (may be null, blank, or prefixed with "Bearer ")
     * @return a {@link TokenValidationResponse} containing:
     *          - valid = true with userId and role if the token is valid
     *          - valid = false with an error message if the token is invalid
     */
    TokenValidationResponse validateToken(String token);

    /**
     * Retrieves the current status of a user registration process.
     * This is typically used to track asynchronous registration workflows
     * initiated via an outbox/event-driven mechanism.
     *
     * @param outboxId the unique identifier of the registration outbox event
     * @return a {@link GetRegistrationStatusDto} containing the current status
     *         of the registration process
     */
    GetRegistrationStatusDto getRegistrationStatus(UUID outboxId);
}