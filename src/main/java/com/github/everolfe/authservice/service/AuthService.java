package com.github.everolfe.authservice.service;

import com.github.everolfe.authservice.dto.GetRefreshTokenDto;
import com.github.everolfe.authservice.dto.auth.CreateAuthDto;
import com.github.everolfe.authservice.dto.auth.GetAuthDto;
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
     * @return {@code true} if registration was successful, {@code false} otherwise
     */
    boolean register(CreateAuthDto createAuthDto);

    /**
     * Authenticates a user and generates access and refresh tokens.
     *
     * @param createAuthDto the user credentials for login
     * @return {@link GetAuthDto} containing the generated access token and refresh token
     */
    GetAuthDto login(CreateAuthDto createAuthDto);

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
     * Validates the provided token and returns its status.
     *
     * @param token the token to validate (can be null or invalid)
     * @return a string indicating the validation result:
     *         - "VALID: username" if token is valid
     *         - "INVALID: reason" if token is invalid
     */
    String validateToken(String token);
}