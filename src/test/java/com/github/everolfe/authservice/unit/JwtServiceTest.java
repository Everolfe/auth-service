package com.github.everolfe.authservice.unit;

import com.github.everolfe.authservice.entity.Role;
import com.github.everolfe.authservice.entity.UserCredential;
import com.github.everolfe.authservice.service.JwtService;
import com.github.everolfe.authservice.service.JwtUserInfo;
import com.github.everolfe.authservice.service.impl.JwtServiceImpl;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
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
    private JwtServiceImpl jwtServiceImpl;

    @Mock
    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        jwtServiceImpl = new JwtServiceImpl();
        ReflectionTestUtils.setField(jwtServiceImpl, "accessTokenExpirationMinutes", 15L);
        ReflectionTestUtils.setField(jwtServiceImpl, "refreshTokenExpirationHours", 2L);
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

        Map<String, String> tokens = jwtServiceImpl.generateTokens(userCredential);

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

        Map<String, String> tokens = jwtServiceImpl.generateTokens(userCredential);
        String accessToken = tokens.get("access_token");

        Claims claims = Jwts.parser()
                .verifyWith(jwtServiceImpl.getPublicKey())
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

        Map<String, String> tokens = jwtServiceImpl.generateTokens(userCredential);
        String accessToken = tokens.get("access_token");

        String extractedSub = jwtServiceImpl.extractSub(accessToken);

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

        Map<String, String> tokens = jwtServiceImpl.generateTokens(userCredential);
        String refreshToken = tokens.get("refresh_token");

        String extractedSub = jwtServiceImpl.extractSub(refreshToken);

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

        Map<String, String> tokens = jwtServiceImpl.generateTokens(userCredential);
        String accessToken = tokens.get("access_token");

        boolean expired = jwtServiceImpl.isTokenExpired(accessToken);

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

        boolean expired = jwtServiceImpl.isTokenExpired(expiredToken);

        assertTrue(expired);
    }

    @Test
    void testIsTokenExpiredForInvalidToken() {
        String invalidToken = "invalid.token.string";

        boolean expired = jwtServiceImpl.isTokenExpired(invalidToken);

        assertTrue(expired);
    }

    @Test
    void testExtractSubThrowsExceptionForInvalidToken() {
        String invalidToken = "invalid.token.string";

        assertThrows(Exception.class, () -> jwtServiceImpl.extractSub(invalidToken));
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

        Map<String, String> tokens = jwtServiceImpl.generateTokens(userCredential);
        String accessToken = tokens.get("access_token");

        Claims claims = Jwts.parser()
                .verifyWith(jwtServiceImpl.getPublicKey())
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

        Map<String, String> tokens = jwtServiceImpl.generateTokens(userCredential);
        String refreshToken = tokens.get("refresh_token");

        Claims claims = Jwts.parser()
                .verifyWith(jwtServiceImpl.getPublicKey())
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

        Map<String, String> tokens = jwtServiceImpl.generateTokens(userCredential);
        String accessToken = tokens.get("access_token");

        String keyId = Jwts.parser()
                .verifyWith(jwtServiceImpl.getPublicKey())
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

        Map<String, String> tokens = jwtServiceImpl.generateTokens(userCredential);
        String refreshToken = tokens.get("refresh_token");

        String keyId = Jwts.parser()
                .verifyWith(jwtServiceImpl.getPublicKey())
                .build()
                .parseSignedClaims(refreshToken)
                .getHeader()
                .getKeyId();

        assertEquals(JwtService.KEY_ID, keyId);
    }

    @Test
    void testPublicKeyIsNotNull() {
        assertNotNull(jwtServiceImpl.getPublicKey());
    }

    @Test
    void testPrivateKeyIsNotNull() {
        assertNotNull(jwtServiceImpl.privateKey);
    }

    @Test
    void testAccessTokenExpirationTime() {
        JwtServiceImpl shortLivedJwtServiceImpl = new JwtServiceImpl();
        ReflectionTestUtils.setField(shortLivedJwtServiceImpl, "accessTokenExpirationMinutes", 0L);
        ReflectionTestUtils.setField(shortLivedJwtServiceImpl, "refreshTokenExpirationHours", 2L);

        UserCredential userCredential = UserCredential.builder()
                .sub(UUID.randomUUID())
                .email("test@example.com")
                .password("encodedPassword")
                .role(Role.ROLE_USER)
                .build();

        Map<String, String> tokens = shortLivedJwtServiceImpl.generateTokens(userCredential);
        String accessToken = tokens.get("access_token");


        boolean expired = shortLivedJwtServiceImpl.isTokenExpired(accessToken);

        assertTrue(expired);
    }


    @Test
    void testExtractSubWithMalformedToken() {
        String malformedToken = "eyJhbGciOiJSUzI1NiJ9.malformed";

        assertThrows(Exception.class, () -> jwtServiceImpl.extractSub(malformedToken));
    }

    @Test
    void testIsTokenExpiredWithNullToken() {
        boolean expired = jwtServiceImpl.isTokenExpired(null);
        assertTrue(expired, "isTokenExpired should return true for null token");
    }
    @Test
    void testValidateTokenAndGetUserId_WithValidAccessToken() {
        UUID sub = UUID.randomUUID();
        UserCredential userCredential = UserCredential.builder()
                .sub(sub)
                .email("test@example.com")
                .password("encodedPassword")
                .role(Role.ROLE_USER)
                .build();

        Map<String, String> tokens = jwtServiceImpl.generateTokens(userCredential);
        String accessToken = tokens.get("access_token");

        JwtUserInfo result = jwtServiceImpl.validateTokenAndGetUserInfo(accessToken);

        assertEquals("ROLE_USER", result.getRole());
    }

    @Test
    void testValidateTokenAndGetUserId_WithValidAccessTokenAndAdminRole() {
        UUID sub = UUID.randomUUID();
        UserCredential userCredential = UserCredential.builder()
                .sub(sub)
                .email("admin@example.com")
                .password("encodedPassword")
                .role(Role.ROLE_ADMIN)
                .build();

        Map<String, String> tokens = jwtServiceImpl.generateTokens(userCredential);
        String accessToken = tokens.get("access_token");

        JwtUserInfo result = jwtServiceImpl.validateTokenAndGetUserInfo(accessToken);

        assertEquals("ROLE_ADMIN", result.getRole());
    }

    @Test
    void testValidateTokenAndGetUserId_WithRefreshToken_ShouldThrowException() {
        UserCredential userCredential = UserCredential.builder()
                .sub(UUID.randomUUID())
                .email("test@example.com")
                .password("encodedPassword")
                .role(Role.ROLE_USER)
                .build();

        Map<String, String> tokens = jwtServiceImpl.generateTokens(userCredential);
        String refreshToken = tokens.get("refresh_token");

        io.jsonwebtoken.JwtException exception = assertThrows(io.jsonwebtoken.JwtException.class,
                () -> jwtServiceImpl.validateTokenAndGetUserInfo(refreshToken));

        assertTrue(exception.getMessage().contains("Invalid token type"));
    }

    @Test
    void testValidateTokenAndGetUserId_WithExpiredToken() {
        JwtServiceImpl shortLivedJwtServiceImpl = new JwtServiceImpl();
        ReflectionTestUtils.setField(shortLivedJwtServiceImpl, "accessTokenExpirationMinutes", 0L);
        ReflectionTestUtils.setField(shortLivedJwtServiceImpl, "refreshTokenExpirationHours", 2L);

        UserCredential userCredential = UserCredential.builder()
                .sub(UUID.randomUUID())
                .email("test@example.com")
                .password("encodedPassword")
                .role(Role.ROLE_USER)
                .build();

        Map<String, String> tokens = shortLivedJwtServiceImpl.generateTokens(userCredential);
        String accessToken = tokens.get("access_token");

        io.jsonwebtoken.JwtException exception = assertThrows(io.jsonwebtoken.JwtException.class,
                () -> shortLivedJwtServiceImpl.validateTokenAndGetUserInfo(accessToken));

        assertTrue(exception.getMessage().contains("Token is expired"));
    }

    @Test
    void testValidateTokenAndGetUserId_WithInvalidToken() {
        String invalidToken = "invalid.token.string";

        io.jsonwebtoken.JwtException exception = assertThrows(io.jsonwebtoken.JwtException.class,
                () -> jwtServiceImpl.validateTokenAndGetUserInfo(invalidToken));

        assertTrue(exception.getMessage().contains("Invalid token"));
    }

    @Test
    void testValidateTokenAndGetUserId_WithMalformedToken() {
        String malformedToken = "eyJhbGciOiJSUzI1NiJ9.malformed";

        io.jsonwebtoken.JwtException exception = assertThrows(io.jsonwebtoken.JwtException.class,
                () -> jwtServiceImpl.validateTokenAndGetUserInfo(malformedToken));

        assertTrue(exception.getMessage().contains("Invalid token"));
    }

}