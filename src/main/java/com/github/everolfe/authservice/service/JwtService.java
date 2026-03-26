package com.github.everolfe.authservice.service;

import com.github.everolfe.authservice.entity.UserCredential;
import java.security.PublicKey;
import java.util.Map;

/**
 * Service interface for JSON Web Token (JWT) operations.
 * Provides methods for token generation, validation, and extraction of token claims.
 */
public interface JwtService {

    /**
     * The identifier for the main RSA key used for signing tokens.
     */
    String KEY_ID = "main-rsa-key";

    /**
     * Extracts the JWT ID (jti) claim from the token.
     *
     * @param token the JWT token
     * @return the JWT ID as a string
     */
    String extractJti(String token);

    /**
     * Extracts the subject (sub) claim from the token, which represents the user ID.
     *
     * @param token the JWT token
     * @return the subject (user ID) as a string
     */
    String extractSub(String token);

    /**
     * Checks whether the token has expired.
     *
     * @param token the JWT token
     * @return {@code true} if the token has expired, {@code false} otherwise
     */
    boolean isTokenExpired(String token);

    /**
     * Generates a pair of access and refresh tokens for the given user.
     *
     * @param userCredential the user credentials entity
     * @return a map containing "accessToken" and "refreshToken" keys with their values
     */
    Map<String, String> generateTokens(UserCredential userCredential);

    /**
     * Retrieves the public key used for token signature verification.
     *
     * @return the public key as a {@link PublicKey} object
     */
    PublicKey getPublicKey();

    /**
     * Determines whether the provided token is a refresh token.
     *
     * @param token the JWT token
     * @return {@code true} if the token is a refresh token, {@code false} otherwise
     */
    boolean isRefreshToken(String token);

    /**
     * Validates the token and extracts the user ID if valid.
     *
     * @param token the JWT token to validate
     * @return the user ID extracted from the token
     * @throws RuntimeException if the token is invalid, expired, or any validation fails
     */
    String validateTokenAndGetUserId(String token);
}