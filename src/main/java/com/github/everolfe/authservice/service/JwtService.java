package com.github.everolfe.authservice.service;

import com.github.everolfe.authservice.entity.UserCredential;
import io.jsonwebtoken.Claims;
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
public class JwtService {

    public static final String KEY_ID = "main-rsa-key";

    private static final SignatureAlgorithm ALGORITHM = SIG.RS256;
    private final KeyPair keyPair = ALGORITHM.keyPair().build();
    public final PrivateKey privateKey;
    @Getter
    public final PublicKey publicKey;


    @Value("${jwt.access-token.expiration-minutes:15}")
    private long accessTokenExpirationMinutes;

    @Value("${jwt.refresh-token.expiration-hours:2}")
    private long refreshTokenExpirationDays;

    public JwtService() {
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }



    public String extractSub(String token) {
        return extractAllClaims(token).getSubject();
    }

    public boolean isTokenExpired(String token) {
        try {
            return extractAllClaims(token).getExpiration().before(new Date());
        } catch (Exception e) {
            return true;
        }
    }

    public Map<String,String> generateTokens(UserCredential userCredential) {
        String accessToken = generateAccessToken(userCredential);
        String refreshToken = generateRefreshToken(userCredential.getSub());

        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", accessToken);
        tokens.put("refresh_token", refreshToken);
        return tokens;
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
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(accessTokenExpirationMinutes, ChronoUnit.MINUTES)))
                .signWith(privateKey, ALGORITHM)
                .compact();
    }

    private String generateRefreshToken(UUID sub) {
        Instant now = Instant.now();
        return Jwts.builder()
                .header().keyId(KEY_ID).and()
                .subject(sub.toString())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(refreshTokenExpirationDays, ChronoUnit.DAYS)))
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
