package com.github.everolfe.authservice.controller;

import com.github.everolfe.authservice.dto.GetRefreshTokenDto;
import com.github.everolfe.authservice.dto.TokenValidationResponse;
import com.github.everolfe.authservice.dto.auth.CreateAuthDto;
import com.github.everolfe.authservice.dto.auth.GetAuthDto;
import com.github.everolfe.authservice.service.impl.AuthServiceImpl;
import jakarta.validation.Valid;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthServiceImpl authServiceImpl;


    /**
     * Authenticates a user and returns access and refresh tokens.
     *
     * @param createAuthDto the user credentials (email/username and password)
     * @return {@link GetAuthDto} containing the generated tokens
     */
    @PostMapping("/login")
    public ResponseEntity<GetAuthDto> login(@Valid @RequestBody CreateAuthDto createAuthDto ) {
        return ResponseEntity.ok(authServiceImpl.login(createAuthDto));
    }

    /**
     * Registers a new user account.
     *
     * @param createAuthDto the user credentials for registration
     * @return success message if registration is successful,
     *         or error message if service is unavailable
     */
    @PostMapping("/register")
    public ResponseEntity<String> register(@Valid @RequestBody CreateAuthDto createAuthDto ) {
        if(authServiceImpl.register(createAuthDto)) {
            return ResponseEntity.ok("User registered successfully");
        } else {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body("Service unavailable. Registration failed");
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
     * Validates a JWT token and returns its status.
     *
     * @param authorization the Authorization header containing the Bearer token (optional)
     * @return "VALID: username" if token is valid,
     *         "INVALID: reason" with 401 status if token is invalid or missing
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
}
