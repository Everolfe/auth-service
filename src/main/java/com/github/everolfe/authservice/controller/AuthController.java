package com.github.everolfe.authservice.controller;

import com.github.everolfe.authservice.dto.GetRefreshTokenDto;
import com.github.everolfe.authservice.dto.GetRegistrationStatusDto;
import com.github.everolfe.authservice.dto.TokenValidationResponse;
import com.github.everolfe.authservice.dto.auth.CreateAuthDto;
import com.github.everolfe.authservice.dto.auth.GetAuthDto;
import com.github.everolfe.authservice.dto.auth.LoginDto;
import com.github.everolfe.authservice.service.AuthService;
import jakarta.validation.Valid;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authServiceImpl;


    /**
     * Authenticates a user and returns access and refresh tokens.
     *
     * @param loginDto the user credentials (email/username and password)
     * @return {@link GetAuthDto} containing the generated tokens
     */
    @PostMapping("/login")
    public ResponseEntity<GetAuthDto> login(@Valid @RequestBody LoginDto loginDto ) {
        return ResponseEntity.ok(authServiceImpl.login(loginDto));
    }

    /**
     * Registers a new user account.
     *
     * @param createAuthDto the user credentials for registration
     * @return success message if registration is successful,
     *         or error message if service is unavailable
     */
    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(@Valid @RequestBody CreateAuthDto createAuthDto) {
        UUID outboxId = authServiceImpl.register(createAuthDto);
        if(outboxId != null) {
            return ResponseEntity.accepted()
                    .header("X-Registration-Id", outboxId.toString())
                    .body(Map.of("message", "Registration initiated", "outboxId", outboxId.toString()));
        } else {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(Map.of("error", "Service unavailable. Registration failed"));
        }
    }

    /**
     * Refreshes the access token using a valid refresh token.
     *
     * @param getRefreshTokenDto the DTO containing the refresh token
     * @return {@link GetAuthDto} containing new access and refresh tokens
     */
    @PostMapping("/refresh")
    public ResponseEntity<GetAuthDto> refresh(@Valid @RequestBody GetRefreshTokenDto getRefreshTokenDto) {
        return ResponseEntity.ok(authServiceImpl.refreshToken(getRefreshTokenDto));
    }

    /**
     * Logs out a user by invalidating the provided refresh token.
     *
     * @param authorization the Authorization header containing the Bearer token
     * @return success message if logout was successful,
     *         or error message if the token format is invalid
     */
    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestHeader("Authorization") String authorization) {
        if (authorization != null && authorization.startsWith("Bearer ")) {
            String refreshToken = authorization.substring(7);
            authServiceImpl.logout(refreshToken);
            return ResponseEntity.ok("Logged out successfully");
        }
        return ResponseEntity.badRequest().body("Invalid token");
    }

    /**
     * Validates a JWT token provided in the Authorization header.
     *
     * @param authorization the Authorization header containing a Bearer token
     *                      (may be null or missing)
     * @return a {@link TokenValidationResponse}:
     *             - 200 OK with {@code valid = true} if the token is valid</li>
     *             - 401 Unauthorized with {@code valid = false} if the token is
     *             missing, expired, or invalid
     */
    @GetMapping("/validate")
    public ResponseEntity<TokenValidationResponse> validate(
            @RequestHeader(value = "Authorization", required = false) String authorization) {

        TokenValidationResponse result = authServiceImpl.validateToken(authorization);

        if (!result.isValid()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(result);
        }

        return ResponseEntity.ok(result);
    }

    /**
     * Retrieves the JSON Web Key Set (JWKS) for token signature verification.
     * This endpoint is used by OAuth2 clients to validate JWT signatures.
     *
     * @return a map containing the JWKS configuration
     */
    @GetMapping("/well-known/jwks.json")
    public ResponseEntity<Map<String,Object>> wellKnownJwks() {
        return ResponseEntity.ok(authServiceImpl.getJwtSet());
    }


    /**
     * Retrieves the status of a user registration process by its unique identifier.
     *
     * @param id the UUID of the registration request (outbox/event identifier)
     * @return a {@link GetRegistrationStatusDto} containing the current status
     *         of the registration process (e.g., pending, completed, failed)
     */
    @GetMapping("/registration/{id}")
    public ResponseEntity<GetRegistrationStatusDto> getRegistration(
            @PathVariable("id") UUID id) {
        GetRegistrationStatusDto statusDto = authServiceImpl.getRegistrationStatus(id);
        return ResponseEntity.ok(statusDto);
    }
}
