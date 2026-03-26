package com.github.everolfe.authservice.controller;

import com.github.everolfe.authservice.dto.GetRefreshTokenDto;
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

    @PostMapping("/login")
    public ResponseEntity<GetAuthDto> login(@Valid @RequestBody CreateAuthDto createAuthDto ) {
        return ResponseEntity.ok(authServiceImpl.login(createAuthDto));
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@Valid @RequestBody CreateAuthDto createAuthDto ) {
        if(authServiceImpl.register(createAuthDto)) {
            return ResponseEntity.ok("User registered successfully");
        } else {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body("Service unavailable. Registration failed");
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<GetAuthDto> refresh(@Valid @RequestBody GetRefreshTokenDto getRefreshTokenDto) {
        return ResponseEntity.ok(authServiceImpl.refreshToken(getRefreshTokenDto));
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestHeader("Authorization") String authorization) {
        if (authorization != null && authorization.startsWith("Bearer ")) {
            String refreshToken = authorization.substring(7);
            authServiceImpl.logout(refreshToken);
            return ResponseEntity.ok("Logged out successfully");
        }
        return ResponseEntity.badRequest().body("Invalid token");
    }

    @GetMapping("/validate")
    public ResponseEntity<String> validate(@RequestHeader(value = "Authorization", required = false) String authorization) {
        String result = authServiceImpl.validateToken(authorization);

        if (result.startsWith("INVALID:")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(result);
        }

        return ResponseEntity.ok(result);
    }

    @GetMapping("/well-known/jwks.json")
    public ResponseEntity<Map<String,Object>> wellKnownJwks() {
        return ResponseEntity.ok(authServiceImpl.getJwtSet());
    }
}
