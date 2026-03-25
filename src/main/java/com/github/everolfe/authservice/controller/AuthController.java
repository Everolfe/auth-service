package com.github.everolfe.authservice.controller;

import com.github.everolfe.authservice.dto.GetRefreshTokenDto;
import com.github.everolfe.authservice.dto.auth.CreateAuthDto;
import com.github.everolfe.authservice.dto.auth.GetAuthDto;
import com.github.everolfe.authservice.service.AuthService;
import jakarta.validation.Valid;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<GetAuthDto> login(@Valid @RequestBody CreateAuthDto createAuthDto ) {
        return ResponseEntity.ok(authService.login(createAuthDto));
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@Valid @RequestBody CreateAuthDto createAuthDto ) {
        if(authService.register(createAuthDto)) {
            return ResponseEntity.ok("User registered successfully");
        } else {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body("Service unavailable. Registration failed");
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<GetAuthDto> refresh(@Valid @RequestBody GetRefreshTokenDto getRefreshTokenDto) {
        return ResponseEntity.ok(authService.refreshToken(getRefreshTokenDto));
    }

    @GetMapping("/validate")
    public ResponseEntity<String> validate() {
        return ResponseEntity.ok("Token is valid");
    }

    @GetMapping("/well-known/jwks.json")
    public ResponseEntity<Map<String,Object>> wellKnownJwks() {
        return ResponseEntity.ok(authService.getJwtSet());
    }
}
