package com.github.everolfe.authservice.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.everolfe.authservice.dao.OutboxRepository;
import com.github.everolfe.authservice.dao.UserCredentialRepository;
import com.github.everolfe.authservice.dto.CreateProfileDto;
import com.github.everolfe.authservice.dto.GetRefreshTokenDto;
import com.github.everolfe.authservice.dto.auth.CreateAuthDto;
import com.github.everolfe.authservice.dto.auth.GetAuthDto;
import com.github.everolfe.authservice.entity.Outbox;
import com.github.everolfe.authservice.entity.OutboxStatus;
import com.github.everolfe.authservice.entity.Role;
import com.github.everolfe.authservice.entity.UserCredential;
import com.github.everolfe.authservice.service.AuthService;
import com.github.everolfe.authservice.service.JwtService;
import io.jsonwebtoken.JwtException;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Map;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.Set;


@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserCredentialRepository userCredentialRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final OutboxRepository outboxRepository;
    private final RedisTemplate<String, String> redisTemplate;
    private final ObjectMapper objectMapper;
    private static final String ACCESS_TOKEN = "access_token";
    private static final String REFRESH_TOKEN = "refresh_token";
    private static final String REFRESH_TOKEN_PREFIX = "refresh_token:";
    private static final String USER_TOKEN_PREFIX = "user_tokens:";

    @Value("${app.userservice.url:http://localhost:8081/api/users/internal/register}")
    private String userServiceUrl;

    @Value("${jwt.refresh-token.expiration-hours:2}")
    private long refreshTokenExpirationHours;

    @Override
    @Transactional
    public boolean register(CreateAuthDto createAuthDto) {
        UUID userSub = UUID.randomUUID();

        try {
            UserCredential userCredential = UserCredential.builder()
                    .sub(userSub)
                    .email(createAuthDto.getEmail())
                    .password(passwordEncoder.encode(createAuthDto.getPassword()))
                    .role(Role.ROLE_USER)
                    .build();
            userCredentialRepository.save(userCredential);

            CreateProfileDto profileDto = createAuthDto.toProfileDto(userSub);
            String payload = objectMapper.writeValueAsString(profileDto);

            Outbox outbox = Outbox.builder()
                    .id(UUID.randomUUID())
                    .payload(payload)
                    .status(OutboxStatus.PENDING)
                    .build();
            outboxRepository.save(outbox);

            return true;

        } catch (JsonProcessingException e) {
            return false;
        }
    }

    @Override
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

            String refreshToken = tokens.get(REFRESH_TOKEN);
            storeRefreshToken(refreshToken, userCredential.getSub());

            return GetAuthDto.builder()
                    .accessToken(tokens.get(ACCESS_TOKEN))
                    .refreshToken(tokens.get(REFRESH_TOKEN))
                    .build();

        } else {
            throw new BadCredentialsException("Invalid user credential");
        }
    }

    @Override
    @Transactional
    public GetAuthDto refreshToken(GetRefreshTokenDto refreshTokenDto) {
        String refreshToken = refreshTokenDto.getRefreshToken();
        if(jwtService.isTokenExpired(refreshToken)) {
            throw new JwtException("Token is expired");
        }

        if (!jwtService.isRefreshToken(refreshToken)) {
            throw new JwtException("Invalid token type");
        }

        String jti = jwtService.extractJti(refreshToken);
        String redisKey = REFRESH_TOKEN_PREFIX + jti;

        if (Boolean.FALSE.equals(redisTemplate.hasKey(redisKey))) {
            throw new JwtException("Token has been revoked or does not exist");
        }

        redisTemplate.delete(redisKey);

        String sub = jwtService.extractSub(refreshToken);

        UserCredential credential = userCredentialRepository
                .findBySub(UUID.fromString(sub))
                .orElseThrow(() -> new BadCredentialsException("Invalid user credential"));

        Map<String,String> tokens = jwtService.generateTokens(credential);

        String newRefreshToken = tokens.get(REFRESH_TOKEN);
        storeRefreshToken(newRefreshToken, credential.getSub());

        return GetAuthDto.builder()
                .accessToken(tokens.get(ACCESS_TOKEN))
                .refreshToken(tokens.get(REFRESH_TOKEN))
                .build();
    }

    @Override
    @Transactional
    public void logout(String refreshToken) {
        String jti = jwtService.extractJti(refreshToken);
        String sub = jwtService.extractSub(refreshToken);
        redisTemplate.delete(REFRESH_TOKEN_PREFIX + jti);
        String userTokensKey = USER_TOKEN_PREFIX + sub;
        redisTemplate.opsForSet().remove(userTokensKey, jti);
    }

    @Override
    @Transactional
    public void revokeAllUserTokens(UUID userSub) {
        String userTokensKey = USER_TOKEN_PREFIX + userSub;
        Set<String> userJtis = redisTemplate.opsForSet().members(userTokensKey);
        if (userJtis != null && !userJtis.isEmpty()) {
            for (String jti : userJtis) {
                redisTemplate.delete(REFRESH_TOKEN_PREFIX + jti);
            }
            redisTemplate.delete(userTokensKey);
        }
    }

    @Override
    public Map<String, Object> getJwtSet() {
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) jwtService.getPublicKey())
                .keyID(JwtService.KEY_ID)
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return jwkSet.toJSONObject();
    }

    @Override
    public String validateToken(String token) {
        if (token == null || token.isBlank()) {
            return "INVALID: Token is required";
        }

        String cleanToken = token.startsWith("Bearer ") ? token.substring(7) : token;

        try {
            return jwtService.validateTokenAndGetUserId(cleanToken);
        } catch (Exception e) {
            return "INVALID: " + e.getMessage();
        }
    }

    private void storeRefreshToken(String refreshToken, UUID userSub) {
        String jti = jwtService.extractJti(refreshToken);

        redisTemplate.opsForValue().set(
                REFRESH_TOKEN_PREFIX + jti,
                userSub.toString(),
                Duration.ofHours(refreshTokenExpirationHours)
        );

        String userTokensKey = USER_TOKEN_PREFIX + userSub;
        redisTemplate.opsForSet().add(userTokensKey, jti);
        redisTemplate.expire(userTokensKey, Duration.ofHours(refreshTokenExpirationHours));
    }
}
