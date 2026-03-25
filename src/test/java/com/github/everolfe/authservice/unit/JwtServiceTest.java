package com.github.everolfe.authservice.unit;

import com.github.everolfe.authservice.entity.Role;
import com.github.everolfe.authservice.entity.UserCredential;
import com.github.everolfe.authservice.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class JwtServiceTest {

    @InjectMocks
    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService();
        ReflectionTestUtils.setField(jwtService, "accessTokenExpirationMinutes", 15L);
        ReflectionTestUtils.setField(jwtService, "refreshTokenExpirationDays", 2L);
    }

    @Test
    void testGenerateTokensSuccess() {
        UUID sub = UUID.randomUUID();
        UserCredential userCredential = UserCredential.builder()
                .id(1L)
                .sub(sub)
                .email("test@example.com")
                .password("encodedPassword")
                .role(Role.ROLE_USER)
                .build();

        Map<String, String> tokens = jwtService.generateTokens(userCredential);

        assertNotNull(tokens);
        assertTrue(tokens.containsKey("access_token"));
        assertTrue(tokens.containsKey("refresh_token"));
        assertNotNull(tokens.get("access_token"));
        assertNotNull(tokens.get("refresh_token"));
        assertNotEquals(tokens.get("access_token"), tokens.get("refresh_token"));
    }

    @Test
    void testGenerateTokensWithAdminRole() {
        UUID sub = UUID.randomUUID();
        UserCredential userCredential = UserCredential.builder()
                .id(1L)
                .sub(sub)
                .email("admin@example.com")
                .password("encodedPassword")
                .role(Role.ROLE_ADMIN)
                .build();

        Map<String, String> tokens = jwtService.generateTokens(userCredential);
        String accessToken = tokens.get("access_token");

        Claims claims = Jwts.parser()
                .verifyWith(jwtService.getPublicKey())
                .build()
                .parseSignedClaims(accessToken)
                .getPayload();

        assertEquals("ROLE_ADMIN", claims.get("scope"));
    }

    @Test
    void testExtractSubFromValidAccessToken() {
        UUID sub = UUID.randomUUID();
        UserCredential userCredential = UserCredential.builder()
                .sub(sub)
                .email("test@example.com")
                .password("encodedPassword")
                .role(Role.ROLE_USER)
                .build();

        Map<String, String> tokens = jwtService.generateTokens(userCredential);
        String accessToken = tokens.get("access_token");

        String extractedSub = jwtService.extractSub(accessToken);

        assertEquals(sub.toString(), extractedSub);
    }

    @Test
    void testExtractSubFromValidRefreshToken() {
        UUID sub = UUID.randomUUID();
        UserCredential userCredential = UserCredential.builder()
                .sub(sub)
                .email("test@example.com")
                .password("encodedPassword")
                .role(Role.ROLE_USER)
                .build();

        Map<String, String> tokens = jwtService.generateTokens(userCredential);
        String refreshToken = tokens.get("refresh_token");

        String extractedSub = jwtService.extractSub(refreshToken);

        assertEquals(sub.toString(), extractedSub);
    }

    @Test
    void testIsTokenExpiredForValidToken() {
        UserCredential userCredential = UserCredential.builder()
                .sub(UUID.randomUUID())
                .email("test@example.com")
                .password("encodedPassword")
                .role(Role.ROLE_USER)
                .build();

        Map<String, String> tokens = jwtService.generateTokens(userCredential);
        String accessToken = tokens.get("access_token");

        boolean expired = jwtService.isTokenExpired(accessToken);

        assertFalse(expired);
    }

    @Test
    void testIsTokenExpiredForExpiredToken() {
        String expiredToken = Jwts.builder()
                .header().keyId(JwtService.KEY_ID).and()
                .subject(UUID.randomUUID().toString())
                .issuedAt(Date.from(Instant.now().minus(2, ChronoUnit.HOURS)))
                .expiration(Date.from(Instant.now().minus(1, ChronoUnit.HOURS)))
                .compact();

        boolean expired = jwtService.isTokenExpired(expiredToken);

        assertTrue(expired);
    }

    @Test
    void testIsTokenExpiredForInvalidToken() {
        String invalidToken = "invalid.token.string";

        boolean expired = jwtService.isTokenExpired(invalidToken);

        assertTrue(expired);
    }

    @Test
    void testExtractSubThrowsExceptionForInvalidToken() {
        String invalidToken = "invalid.token.string";

        assertThrows(Exception.class, () -> jwtService.extractSub(invalidToken));
    }

    @Test
    void testAccessTokenContainsScopeClaim() {
        UUID sub = UUID.randomUUID();
        UserCredential userCredential = UserCredential.builder()
                .sub(sub)
                .email("test@example.com")
                .password("encodedPassword")
                .role(Role.ROLE_ADMIN)
                .build();

        Map<String, String> tokens = jwtService.generateTokens(userCredential);
        String accessToken = tokens.get("access_token");

        Claims claims = Jwts.parser()
                .verifyWith(jwtService.getPublicKey())
                .build()
                .parseSignedClaims(accessToken)
                .getPayload();

        assertEquals(sub.toString(), claims.getSubject());
        assertEquals("ROLE_ADMIN", claims.get("scope"));
    }

    @Test
    void testRefreshTokenHasNoScopeClaim() {
        UserCredential userCredential = UserCredential.builder()
                .sub(UUID.randomUUID())
                .email("test@example.com")
                .password("encodedPassword")
                .role(Role.ROLE_USER)
                .build();

        Map<String, String> tokens = jwtService.generateTokens(userCredential);
        String refreshToken = tokens.get("refresh_token");

        Claims claims = Jwts.parser()
                .verifyWith(jwtService.getPublicKey())
                .build()
                .parseSignedClaims(refreshToken)
                .getPayload();


        assertNull(claims.get("scope"));
    }

    @Test
    void testAccessTokenHasKeyIdHeader() {

        UserCredential userCredential = UserCredential.builder()
                .sub(UUID.randomUUID())
                .email("test@example.com")
                .password("encodedPassword")
                .role(Role.ROLE_USER)
                .build();

        Map<String, String> tokens = jwtService.generateTokens(userCredential);
        String accessToken = tokens.get("access_token");

        String keyId = Jwts.parser()
                .verifyWith(jwtService.getPublicKey())
                .build()
                .parseSignedClaims(accessToken)
                .getHeader()
                .getKeyId();

        assertEquals(JwtService.KEY_ID, keyId);
    }

    @Test
    void testRefreshTokenHasKeyIdHeader() {
        UserCredential userCredential = UserCredential.builder()
                .sub(UUID.randomUUID())
                .email("test@example.com")
                .password("encodedPassword")
                .role(Role.ROLE_USER)
                .build();

        Map<String, String> tokens = jwtService.generateTokens(userCredential);
        String refreshToken = tokens.get("refresh_token");

        String keyId = Jwts.parser()
                .verifyWith(jwtService.getPublicKey())
                .build()
                .parseSignedClaims(refreshToken)
                .getHeader()
                .getKeyId();

        assertEquals(JwtService.KEY_ID, keyId);
    }

    @Test
    void testPublicKeyIsNotNull() {
        assertNotNull(jwtService.getPublicKey());
    }

    @Test
    void testPrivateKeyIsNotNull() {
        assertNotNull(jwtService.privateKey);
    }

    @Test
    void testAccessTokenExpirationTime() throws InterruptedException {
        JwtService shortLivedJwtService = new JwtService();
        ReflectionTestUtils.setField(shortLivedJwtService, "accessTokenExpirationMinutes", 0L);
        ReflectionTestUtils.setField(shortLivedJwtService, "refreshTokenExpirationDays", 2L);

        UserCredential userCredential = UserCredential.builder()
                .sub(UUID.randomUUID())
                .email("test@example.com")
                .password("encodedPassword")
                .role(Role.ROLE_USER)
                .build();

        Map<String, String> tokens = shortLivedJwtService.generateTokens(userCredential);
        String accessToken = tokens.get("access_token");

        Thread.sleep(100);

        boolean expired = shortLivedJwtService.isTokenExpired(accessToken);

        assertTrue(expired);
    }

    @Test
    void testGenerateTokensForSameUserProducesDifferentTokens() throws InterruptedException {
        UUID sub = UUID.randomUUID();
        UserCredential userCredential = UserCredential.builder()
                .sub(sub)
                .email("test@example.com")
                .password("encodedPassword")
                .role(Role.ROLE_USER)
                .build();

        Map<String, String> tokens1 = jwtService.generateTokens(userCredential);

        Thread.sleep(1500);

        Map<String, String> tokens2 = jwtService.generateTokens(userCredential);

        Claims claims1 = Jwts.parser()
                .verifyWith(jwtService.getPublicKey())
                .build()
                .parseSignedClaims(tokens1.get("access_token"))
                .getPayload();

        Claims claims2 = Jwts.parser()
                .verifyWith(jwtService.getPublicKey())
                .build()
                .parseSignedClaims(tokens2.get("access_token"))
                .getPayload();

        assertNotEquals(claims1.getIssuedAt(), claims2.getIssuedAt(),
                "Issued at times should be different");

        assertNotEquals(tokens1.get("access_token"), tokens2.get("access_token"));
        assertNotEquals(tokens1.get("refresh_token"), tokens2.get("refresh_token"));
    }

    @Test
    void testExtractSubWithMalformedToken() {
        String malformedToken = "eyJhbGciOiJSUzI1NiJ9.malformed";

        assertThrows(Exception.class, () -> jwtService.extractSub(malformedToken));
    }

    @Test
    void testIsTokenExpiredWithNullToken() {
        boolean expired = jwtService.isTokenExpired(null);
        assertTrue(expired, "isTokenExpired should return true for null token");
    }
}