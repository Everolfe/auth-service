package com.github.everolfe.authservice.service;

import com.github.everolfe.authservice.dao.UserCredentialRepository;
import com.github.everolfe.authservice.dto.CreateProfileDto;
import com.github.everolfe.authservice.dto.GetRefreshTokenDto;
import com.github.everolfe.authservice.dto.auth.CreateAuthDto;
import com.github.everolfe.authservice.dto.auth.GetAuthDto;
import com.github.everolfe.authservice.entity.Role;
import com.github.everolfe.authservice.entity.UserCredential;
import io.jsonwebtoken.JwtException;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserCredentialRepository userCredentialRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RestTemplate restTemplate;

    @Value("${app.userservice.url:http://localhost:8081/api/users/internal/register}")
    private String userServiceUrl;


    @Transactional
    public boolean register(CreateAuthDto createAuthDto) {
        UserCredential userCredential = UserCredential.builder()
                .sub(UUID.randomUUID())
                .email(createAuthDto.getEmail())
                .password(passwordEncoder.encode(createAuthDto.getPassword()))
                .role(Role.ROLE_USER)
                .build();

        CreateProfileDto profileDto = createAuthDto.toProfileDto(userCredential.getSub());
        try{
            restTemplate.postForObject(userServiceUrl, profileDto, String.class);
            userCredentialRepository.save(userCredential);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Transactional
    public GetAuthDto login(CreateAuthDto createAuthDto) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        createAuthDto.getEmail(),
                        createAuthDto.getPassword()
                )
        );

        if(authentication.isAuthenticated()) {
            UserCredential userCredential = (UserCredential) authentication.getPrincipal();

            Map<String,String> tokens = jwtService.generateTokens(userCredential);

            return GetAuthDto.builder()
                    .accessToken(tokens.get("access_token"))
                    .refreshToken(tokens.get("refresh_token"))
                    .build();

        } else {
            throw new BadCredentialsException("Invalid user credential");
        }
    }

    @Transactional
    public GetAuthDto refreshToken(GetRefreshTokenDto refreshTokenDto) {
        String refreshToken = refreshTokenDto.getRefreshToken();
        if(jwtService.isTokenExpired(refreshToken)) {
            throw new JwtException("Token is expired");
        }

        String sub = jwtService.extractSub(refreshToken);

        UserCredential credential = userCredentialRepository
                .findBySub(UUID.fromString(sub))
                .orElseThrow(() -> new BadCredentialsException("Invalid user credential"));

        Map<String,String> tokens = jwtService.generateTokens(credential);

        return GetAuthDto.builder()
                .accessToken(tokens.get("access_token"))
                .refreshToken(tokens.get("refresh_token"))
                .build();
    }


    public Map<String, Object> getJwtSet() {
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) jwtService.getPublicKey())
                .keyID(JwtService.KEY_ID)
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return jwkSet.toJSONObject();
    }
}
