package com.github.everolfe.authservice.service.impl;

import com.github.everolfe.authservice.entity.UserCredential;
import com.github.everolfe.authservice.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Jwts.SIG;
import io.jsonwebtoken.security.SignatureAlgorithm;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.security.core.GrantedAuthority;


@Service
@RequiredArgsConstructor
public class JwtServiceImpl implements JwtService {

    private static final String KEY_ID = JwtService.KEY_ID;

    private static final SignatureAlgorithm ALGORITHM = SIG.RS256;
    private final KeyPair keyPair = ALGORITHM.keyPair().build();
    public final PrivateKey privateKey;
    @Getter
    public final PublicKey publicKey;


    @Value("${jwt.access-token.expiration-minutes:15}")
    private long accessTokenExpirationMinutes;

    @Value("${jwt.refresh-token.expiration-hours:2}")
    private long refreshTokenExpirationHours;

    public JwtServiceImpl() {
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }


    @Override
    public String extractSub(String token) {
        return extractAllClaims(token).getSubject();
    }

    @Override
    public boolean isTokenExpired(String token) {
        try {
            return extractAllClaims(token).getExpiration().before(new Date());
        } catch (Exception e) {
            return true;
        }
    }

    @Override
    public Map<String,String> generateTokens(UserCredential userCredential) {
        String accessToken = generateAccessToken(userCredential);
        String refreshToken = generateRefreshToken(userCredential.getSub());

        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", accessToken);
        tokens.put("refresh_token", refreshToken);
        return tokens;
    }

    @Override
    public boolean isRefreshToken(String token) {
        try {
            Claims claims = extractAllClaims(token);
            return "REFRESH".equals(claims.get("type", String.class));
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public String validateTokenAndGetUserId(String token) {
        try {
            if (isRefreshToken(token)) {
                throw new JwtException("Invalid token type: refresh token not allowed");
            }

            if (isTokenExpired(token)) {
                throw new JwtException("Token is expired");
            }

            Claims claims = extractAllClaims(token);
            String userId = claims.getSubject();
            String scope = claims.get("scope", String.class);

            String role = scope != null ? scope.split(" ")[0] : "ROLE_USER";
            return userId + ":" + role;

        } catch (Exception e) {
            throw new JwtException("Invalid token: " + e.getMessage());
        }
    }

    @Override
    public String extractJti(String token) {
        return extractAllClaims(token).getId();
    }

    private String generateAccessToken(UserCredential userCredential) {
        Instant now = Instant.now();

        String scope = userCredential.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));

        return Jwts.builder()
                .header().keyId(KEY_ID).and()
                .subject(userCredential.getSub().toString())
                .claim("scope", scope)
                .claim("type", "ACCESS")
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(accessTokenExpirationMinutes, ChronoUnit.MINUTES)))
                .signWith(privateKey, ALGORITHM)
                .compact();
    }

    private String generateRefreshToken(UUID sub) {
        Instant now = Instant.now();
        String jti = UUID.randomUUID().toString();
        return Jwts.builder()
                .header().keyId(KEY_ID).and()
                .id(jti)
                .subject(sub.toString())
                .claim("type", "REFRESH")
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(refreshTokenExpirationHours, ChronoUnit.HOURS)))
                .signWith(privateKey, ALGORITHM)
                .compact();
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

}
