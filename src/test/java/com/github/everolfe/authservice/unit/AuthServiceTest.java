package com.github.everolfe.authservice.unit;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.everolfe.authservice.dao.OutboxRepository;
import com.github.everolfe.authservice.dao.UserCredentialRepository;
import com.github.everolfe.authservice.dto.CreateProfileDto;
import com.github.everolfe.authservice.dto.GetRefreshTokenDto;
import com.github.everolfe.authservice.dto.TokenValidationResponse;
import com.github.everolfe.authservice.dto.auth.CreateAuthDto;
import com.github.everolfe.authservice.dto.auth.GetAuthDto;
import com.github.everolfe.authservice.entity.Outbox;
import com.github.everolfe.authservice.entity.Role;
import com.github.everolfe.authservice.entity.UserCredential;
import com.github.everolfe.authservice.service.JwtService;
import com.github.everolfe.authservice.service.JwtUserInfo;
import com.github.everolfe.authservice.service.impl.AuthServiceImpl;
import com.github.everolfe.authservice.service.impl.JwtServiceImpl;
import io.jsonwebtoken.JwtException;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.redis.core.SetOperations;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDate;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private UserCredentialRepository userCredentialRepository;

    @Mock
    private OutboxRepository outboxRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtServiceImpl jwtServiceImpl;

    @Mock
    private RestTemplate restTemplate;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private RedisTemplate<String, String> redisTemplate;

    @Mock
    private ValueOperations<String, String> valueOperations;

    @Mock
    private SetOperations<String, String> setOperations;

    @InjectMocks
    private AuthServiceImpl authServiceImpl;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(authServiceImpl, "userServiceUrl", "http://localhost:8081/api/users/internal/register");
    }

    @Test
    void testRegisterSuccess() throws JsonProcessingException {
        CreateAuthDto createAuthDto = new CreateAuthDto();
        createAuthDto.setEmail("test@example.com");
        createAuthDto.setPassword("password123");
        createAuthDto.setName("John");
        createAuthDto.setSurname("Doe");
        createAuthDto.setBirthDate(LocalDate.of(1990, 1, 1));

        String encodedPassword = "encodedPassword";

        when(passwordEncoder.encode(createAuthDto.getPassword())).thenReturn(encodedPassword);
        when(userCredentialRepository.save(any(UserCredential.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(objectMapper.writeValueAsString(any(CreateProfileDto.class)))
                .thenReturn("{\"sub\":\"test\",\"email\":\"test@example.com\"}");
        when(outboxRepository.save(any(Outbox.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        boolean result = authServiceImpl.register(createAuthDto);

        assertTrue(result);
        verify(passwordEncoder, times(1)).encode("password123");
        verify(userCredentialRepository, times(1)).save(any(UserCredential.class));
        verify(objectMapper, times(1)).writeValueAsString(any(CreateProfileDto.class));
        verify(outboxRepository, times(1)).save(any(Outbox.class));
        verify(restTemplate, never()).postForObject(anyString(), any(), any());
    }

    @Test
    void testRegisterWithJsonProcessingException() throws JsonProcessingException {
        CreateAuthDto createAuthDto = new CreateAuthDto();
        createAuthDto.setEmail("test@example.com");
        createAuthDto.setPassword("password123");

        when(passwordEncoder.encode(createAuthDto.getPassword())).thenReturn("encodedPassword");
        when(userCredentialRepository.save(any(UserCredential.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(objectMapper.writeValueAsString(any(CreateProfileDto.class)))
                .thenThrow(new JsonProcessingException("JSON error") {});

        boolean result = authServiceImpl.register(createAuthDto);

        assertFalse(result);
        verify(userCredentialRepository, times(1)).save(any(UserCredential.class));
        verify(objectMapper, times(1)).writeValueAsString(any(CreateProfileDto.class));
        verify(outboxRepository, never()).save(any(Outbox.class));
    }

    @Test
    void testLoginSuccess() {
        CreateAuthDto createAuthDto = new CreateAuthDto();
        createAuthDto.setEmail("test@example.com");
        createAuthDto.setPassword("password123");

        UUID sub = UUID.randomUUID();
        UserCredential userCredential = UserCredential.builder()
                .id(1L)
                .sub(sub)
                .email("test@example.com")
                .password("encodedPassword")
                .role(Role.ROLE_USER)
                .build();

        Authentication authentication = mock(Authentication.class);
        Map<String, String> tokens = Map.of(
                "access_token", "access-token-value",
                "refresh_token", "refresh-token-value"
        );

        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(redisTemplate.opsForSet()).thenReturn(setOperations);
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getPrincipal()).thenReturn(userCredential);
        when(jwtServiceImpl.generateTokens(userCredential)).thenReturn(tokens);
        when(jwtServiceImpl.extractJti(anyString())).thenReturn("test-jti");

        GetAuthDto result = authServiceImpl.login(createAuthDto);

        assertNotNull(result);
        assertEquals("access-token-value", result.getAccessToken());
        assertEquals("refresh-token-value", result.getRefreshToken());

        verify(authenticationManager, times(1)).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(jwtServiceImpl, times(1)).generateTokens(userCredential);
        verify(valueOperations, times(1)).set(anyString(), anyString(), any());
        verify(setOperations, times(1)).add(anyString(), anyString());
    }

    @Test
    void testLoginWithInvalidCredentials() {
        CreateAuthDto createAuthDto = new CreateAuthDto();
        createAuthDto.setEmail("test@example.com");
        createAuthDto.setPassword("wrongpassword");

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Invalid credentials"));

        assertThrows(BadCredentialsException.class, () -> authServiceImpl.login(createAuthDto));

        verify(authenticationManager, times(1)).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(jwtServiceImpl, never()).generateTokens(any());
    }

    @Test
    void testLoginWithUnauthenticatedUser() {
        CreateAuthDto createAuthDto = new CreateAuthDto();
        createAuthDto.setEmail("test@example.com");
        createAuthDto.setPassword("password123");

        Authentication authentication = mock(Authentication.class);

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(false);

        assertThrows(BadCredentialsException.class, () -> authServiceImpl.login(createAuthDto));

        verify(jwtServiceImpl, never()).generateTokens(any());
    }

    @Test
    void testRefreshTokenSuccess() {
        GetRefreshTokenDto refreshTokenDto = new GetRefreshTokenDto();
        String refreshTokenValue = "valid-refresh-token";
        refreshTokenDto.setRefreshToken(refreshTokenValue);

        UUID sub = UUID.randomUUID();
        UserCredential userCredential = UserCredential.builder()
                .id(1L)
                .sub(sub)
                .email("test@example.com")
                .role(Role.ROLE_USER)
                .build();

        Map<String, String> tokens = Map.of(
                "access_token", "new-access-token",
                "refresh_token", "new-refresh-token"
        );

        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(redisTemplate.opsForSet()).thenReturn(setOperations);
        when(jwtServiceImpl.isTokenExpired(refreshTokenValue)).thenReturn(false);
        when(jwtServiceImpl.isRefreshToken(refreshTokenValue)).thenReturn(true);
        when(jwtServiceImpl.extractJti(refreshTokenValue)).thenReturn("test-jti");
        when(jwtServiceImpl.extractSub(refreshTokenValue)).thenReturn(sub.toString());
        when(redisTemplate.hasKey(anyString())).thenReturn(true);
        when(userCredentialRepository.findBySub(sub)).thenReturn(Optional.of(userCredential));
        when(jwtServiceImpl.generateTokens(userCredential)).thenReturn(tokens);

        GetAuthDto result = authServiceImpl.refreshToken(refreshTokenDto);

        assertNotNull(result);
        assertEquals("new-access-token", result.getAccessToken());
        assertEquals("new-refresh-token", result.getRefreshToken());

        verify(jwtServiceImpl, times(1)).isTokenExpired(refreshTokenValue);
        verify(jwtServiceImpl, times(1)).extractSub(refreshTokenValue);
        verify(userCredentialRepository, times(1)).findBySub(sub);
        verify(jwtServiceImpl, times(1)).generateTokens(userCredential);
    }

    @Test
    void testRefreshTokenWithExpiredToken() {
        GetRefreshTokenDto refreshTokenDto = new GetRefreshTokenDto();
        String refreshTokenValue = "expired-refresh-token";
        refreshTokenDto.setRefreshToken(refreshTokenValue);

        when(jwtServiceImpl.isTokenExpired(refreshTokenValue)).thenReturn(true);

        assertThrows(JwtException.class, () -> authServiceImpl.refreshToken(refreshTokenDto));

        verify(jwtServiceImpl, times(1)).isTokenExpired(refreshTokenValue);
        verify(jwtServiceImpl, never()).extractSub(any());
        verify(userCredentialRepository, never()).findBySub(any());
    }

    @Test
    void testRefreshTokenWithInvalidSubject() {
        GetRefreshTokenDto refreshTokenDto = new GetRefreshTokenDto();
        String refreshTokenValue = "valid-refresh-token";
        refreshTokenDto.setRefreshToken(refreshTokenValue);

        UUID sub = UUID.randomUUID();

        when(jwtServiceImpl.isTokenExpired(refreshTokenValue)).thenReturn(false);
        when(jwtServiceImpl.isRefreshToken(refreshTokenValue)).thenReturn(true);
        when(jwtServiceImpl.extractJti(refreshTokenValue)).thenReturn("test-jti");
        when(jwtServiceImpl.extractSub(refreshTokenValue)).thenReturn(sub.toString());
        when(redisTemplate.hasKey(anyString())).thenReturn(true);
        when(userCredentialRepository.findBySub(sub)).thenReturn(Optional.empty());

        assertThrows(BadCredentialsException.class, () -> authServiceImpl.refreshToken(refreshTokenDto));

        verify(jwtServiceImpl, times(1)).isTokenExpired(refreshTokenValue);
        verify(jwtServiceImpl, times(1)).extractSub(refreshTokenValue);
        verify(userCredentialRepository, times(1)).findBySub(sub);
        verify(jwtServiceImpl, never()).generateTokens(any());
    }

    @Test
    void testRefreshTokenWithMalformedSub() {
        GetRefreshTokenDto refreshTokenDto = new GetRefreshTokenDto();
        String refreshTokenValue = "valid-refresh-token";
        refreshTokenDto.setRefreshToken(refreshTokenValue);

        when(jwtServiceImpl.isTokenExpired(refreshTokenValue)).thenReturn(false);
        when(jwtServiceImpl.isRefreshToken(refreshTokenValue)).thenReturn(true);
        when(jwtServiceImpl.extractJti(refreshTokenValue)).thenReturn("test-jti");
        when(jwtServiceImpl.extractSub(refreshTokenValue)).thenReturn("not-a-valid-uuid");
        when(redisTemplate.hasKey(anyString())).thenReturn(true);

        assertThrows(IllegalArgumentException.class, () -> authServiceImpl.refreshToken(refreshTokenDto));

        verify(jwtServiceImpl, times(1)).isTokenExpired(refreshTokenValue);
        verify(jwtServiceImpl, times(1)).extractSub(refreshTokenValue);
        verify(userCredentialRepository, never()).findBySub(any());
    }

    @Test
    void testGetJwtSetSuccess() {
        RSAPublicKey mockPublicKey = mock(RSAPublicKey.class);
        when(mockPublicKey.getModulus()).thenReturn(new java.math.BigInteger("123456789"));
        when(mockPublicKey.getPublicExponent()).thenReturn(java.math.BigInteger.valueOf(65537));
        when(jwtServiceImpl.getPublicKey()).thenReturn(mockPublicKey);

        Map<String, Object> result = authServiceImpl.getJwtSet();

        assertNotNull(result);
        assertTrue(result.containsKey("keys"));

        Object keys = result.get("keys");
        assertNotNull(keys);
        assertTrue(keys instanceof java.util.List);

        List<?> keyList = (List<?>) keys;
        assertFalse(keyList.isEmpty());

        Map<String, Object> firstKey = (Map<String, Object>) keyList.get(0);
        assertTrue(firstKey.containsKey("kty"));
        assertEquals("RSA", firstKey.get("kty"));
        assertTrue(firstKey.containsKey("kid"));
        assertEquals(JwtService.KEY_ID, firstKey.get("kid"));

        verify(jwtServiceImpl, atLeastOnce()).getPublicKey();
    }

    @Test
    void testRegisterCreatesProfileDtoWithAllFields() throws JsonProcessingException {
        CreateAuthDto createAuthDto = new CreateAuthDto();
        createAuthDto.setEmail("test@example.com");
        createAuthDto.setPassword("password123");
        createAuthDto.setName("John");
        createAuthDto.setSurname("Doe");
        createAuthDto.setBirthDate(LocalDate.of(1990, 5, 15));

        when(passwordEncoder.encode(createAuthDto.getPassword())).thenReturn("encodedPassword");
        when(objectMapper.writeValueAsString(any(CreateProfileDto.class)))
                .thenReturn("{\"sub\":\"test\",\"email\":\"test@example.com\"}");
        when(outboxRepository.save(any(Outbox.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(userCredentialRepository.save(any(UserCredential.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        ArgumentCaptor<CreateProfileDto> profileDtoCaptor = ArgumentCaptor.forClass(CreateProfileDto.class);

        authServiceImpl.register(createAuthDto);

        verify(objectMapper).writeValueAsString(profileDtoCaptor.capture());

        CreateProfileDto capturedProfileDto = profileDtoCaptor.getValue();
        assertNotNull(capturedProfileDto.getSub());
        assertEquals("John", capturedProfileDto.getName());
        assertEquals("Doe", capturedProfileDto.getSurname());
        assertEquals("test@example.com", capturedProfileDto.getEmail());
        assertEquals(LocalDate.of(1990, 5, 15), capturedProfileDto.getBirthDate());

        verify(restTemplate, never()).postForObject(anyString(), any(), any());
    }

    @Test
    void testRegisterCreatesProfileDtoWithoutOptionalFields() throws JsonProcessingException {
        CreateAuthDto createAuthDto = new CreateAuthDto();
        createAuthDto.setEmail("test@example.com");
        createAuthDto.setPassword("password123");

        when(passwordEncoder.encode(createAuthDto.getPassword())).thenReturn("encodedPassword");
        when(objectMapper.writeValueAsString(any(CreateProfileDto.class)))
                .thenReturn("{\"sub\":\"test\",\"email\":\"test@example.com\"}");
        when(outboxRepository.save(any(Outbox.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(userCredentialRepository.save(any(UserCredential.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        ArgumentCaptor<CreateProfileDto> profileDtoCaptor = ArgumentCaptor.forClass(CreateProfileDto.class);

        authServiceImpl.register(createAuthDto);

        verify(objectMapper).writeValueAsString(profileDtoCaptor.capture());

        CreateProfileDto capturedProfileDto = profileDtoCaptor.getValue();
        assertNotNull(capturedProfileDto.getSub());
        assertEquals("test@example.com", capturedProfileDto.getEmail());
        assertNull(capturedProfileDto.getName());
        assertNull(capturedProfileDto.getSurname());
        assertNull(capturedProfileDto.getBirthDate());

        verify(restTemplate, never()).postForObject(anyString(), any(), any());
    }

    @Test
    void testLoginCreatesCorrectAuthenticationToken() {
        CreateAuthDto createAuthDto = new CreateAuthDto();
        createAuthDto.setEmail("test@example.com");
        createAuthDto.setPassword("password123");

        UUID sub = UUID.randomUUID();
        UserCredential userCredential = UserCredential.builder()
                .sub(sub)
                .email("test@example.com")
                .role(Role.ROLE_USER)
                .build();

        Authentication authentication = mock(Authentication.class);
        Map<String, String> tokens = Map.of(
                "access_token", "access-token",
                "refresh_token", "refresh-token"
        );

        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(redisTemplate.opsForSet()).thenReturn(setOperations);
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getPrincipal()).thenReturn(userCredential);
        when(jwtServiceImpl.generateTokens(userCredential)).thenReturn(tokens);
        when(jwtServiceImpl.extractJti(anyString())).thenReturn("test-jti");

        authServiceImpl.login(createAuthDto);

        verify(authenticationManager).authenticate(argThat(token -> {
            UsernamePasswordAuthenticationToken authToken = (UsernamePasswordAuthenticationToken) token;
            return "test@example.com".equals(authToken.getPrincipal()) &&
                    "password123".equals(authToken.getCredentials());
        }));
    }

    @Test
    void testRegisterSavesUserWithCorrectRoleAndSub() throws JsonProcessingException {
        CreateAuthDto createAuthDto = new CreateAuthDto();
        createAuthDto.setEmail("test@example.com");
        createAuthDto.setPassword("password123");
        createAuthDto.setName("John");
        createAuthDto.setSurname("Doe");

        when(passwordEncoder.encode(createAuthDto.getPassword())).thenReturn("encodedPassword");
        when(objectMapper.writeValueAsString(any(CreateProfileDto.class)))
                .thenReturn("{\"sub\":\"test\",\"email\":\"test@example.com\"}");
        when(outboxRepository.save(any(Outbox.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        ArgumentCaptor<UserCredential> userCredentialCaptor = ArgumentCaptor.forClass(UserCredential.class);

        authServiceImpl.register(createAuthDto);

        verify(userCredentialRepository).save(userCredentialCaptor.capture());

        UserCredential savedCredential = userCredentialCaptor.getValue();
        assertEquals(Role.ROLE_USER, savedCredential.getRole());
        assertEquals("test@example.com", savedCredential.getEmail());
        assertEquals("encodedPassword", savedCredential.getPassword());
        assertNotNull(savedCredential.getSub());
    }

    @Test
    void testRegisterGeneratesUniqueSubForEachUser() throws JsonProcessingException {
        CreateAuthDto createAuthDto1 = new CreateAuthDto();
        createAuthDto1.setEmail("user1@example.com");
        createAuthDto1.setPassword("password123");

        CreateAuthDto createAuthDto2 = new CreateAuthDto();
        createAuthDto2.setEmail("user2@example.com");
        createAuthDto2.setPassword("password456");

        when(passwordEncoder.encode(anyString())).thenReturn("encodedPassword");
        when(objectMapper.writeValueAsString(any(CreateProfileDto.class)))
                .thenReturn("{\"sub\":\"test\",\"email\":\"test@example.com\"}");
        when(outboxRepository.save(any(Outbox.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        ArgumentCaptor<UserCredential> userCaptor1 = ArgumentCaptor.forClass(UserCredential.class);

        authServiceImpl.register(createAuthDto1);
        authServiceImpl.register(createAuthDto2);

        verify(userCredentialRepository, times(2)).save(userCaptor1.capture());

        UserCredential user1 = userCaptor1.getAllValues().get(0);
        UserCredential user2 = userCaptor1.getAllValues().get(1);

        assertNotEquals(user1.getSub(), user2.getSub(), "Sub values should be unique");
    }

    @Test
    void testValidateToken_WithValidToken() {
        String validToken = "valid-jwt-token";
        String expectedUserId = "user-uuid-123";
        JwtUserInfo expectedResponse = new JwtUserInfo(expectedUserId,"ROLE_USER");
        when(jwtServiceImpl.validateTokenAndGetUserInfo(validToken)).thenReturn(expectedResponse);

        TokenValidationResponse result = authServiceImpl.validateToken(validToken);

        assertEquals(expectedUserId, result.getUserId());
        verify(jwtServiceImpl, times(1)).validateTokenAndGetUserInfo(validToken);
    }

    @Test
    void testValidateToken_WithBearerPrefix() {
        String bearerToken = "Bearer valid-jwt-token";
        String cleanToken = "valid-jwt-token";
        String expectedUserId = "user-uuid-123";
        JwtUserInfo expectedResponse = new JwtUserInfo(expectedUserId,"ROLE_USER");
        when(jwtServiceImpl.validateTokenAndGetUserInfo(cleanToken)).thenReturn(expectedResponse);

        TokenValidationResponse result = authServiceImpl.validateToken(bearerToken);

        assertEquals(expectedUserId, result.getUserId());
        verify(jwtServiceImpl, times(1)).validateTokenAndGetUserInfo(cleanToken);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t", "\n", "  \t  "})
    void testValidateToken_WithNullOrBlankToken(String token) {
        TokenValidationResponse result = authServiceImpl.validateToken(token);

        assertFalse(result.isValid());
        verify(jwtServiceImpl, never()).validateTokenAndGetUserInfo(anyString());
    }

    @Test
    void testValidateToken_WithInvalidToken() {
        String invalidToken = "invalid-token";
        String errorMessage = "Token expired";

        when(jwtServiceImpl.validateTokenAndGetUserInfo(invalidToken))
                .thenThrow(new JwtException(errorMessage));

        TokenValidationResponse result = authServiceImpl.validateToken(invalidToken);

        assertFalse(result.isValid());
        verify(jwtServiceImpl, times(1)).validateTokenAndGetUserInfo(invalidToken);
    }

    @Test
    void testLogout_Success() {
        String refreshToken = "valid-refresh-token";
        String jti = "test-jti-123";
        String sub = "123e4567-e89b-12d3-a456-426614174000";

        when(jwtServiceImpl.extractJti(refreshToken)).thenReturn(jti);
        when(jwtServiceImpl.extractSub(refreshToken)).thenReturn(sub);
        when(redisTemplate.opsForSet()).thenReturn(setOperations);

        authServiceImpl.logout(refreshToken);

        verify(jwtServiceImpl, times(1)).extractJti(refreshToken);
        verify(jwtServiceImpl, times(1)).extractSub(refreshToken);
        verify(redisTemplate, times(1)).delete("refresh_token:" + jti);
        verify(setOperations, times(1)).remove("user_tokens:" + sub, jti);
    }

    @Test
    void testLogout_WithRedisOperations() {
        String refreshToken = "valid-refresh-token";
        String jti = "test-jti-123";
        String sub = "123e4567-e89b-12d3-a456-426614174000";

        when(jwtServiceImpl.extractJti(refreshToken)).thenReturn(jti);
        when(jwtServiceImpl.extractSub(refreshToken)).thenReturn(sub);
        when(redisTemplate.opsForSet()).thenReturn(setOperations);

        authServiceImpl.logout(refreshToken);

        verify(redisTemplate).delete("refresh_token:" + jti);
        verify(setOperations).remove("user_tokens:" + sub, jti);
    }

    @Test
    void testRevokeAllUserTokens_WithExistingTokens() {
        UUID userSub = UUID.randomUUID();
        String userTokensKey = "user_tokens:" + userSub;
        Set<String> userJtis = Set.of("jti-1", "jti-2", "jti-3");

        when(redisTemplate.opsForSet()).thenReturn(setOperations);
        when(setOperations.members(userTokensKey)).thenReturn(userJtis);

        authServiceImpl.revokeAllUserTokens(userSub);

        verify(setOperations, times(1)).members(userTokensKey);
        verify(redisTemplate, times(1)).delete("refresh_token:jti-1");
        verify(redisTemplate, times(1)).delete("refresh_token:jti-2");
        verify(redisTemplate, times(1)).delete("refresh_token:jti-3");
        verify(redisTemplate, times(1)).delete(userTokensKey);
    }

    @Test
    void testRevokeAllUserTokens_WithEmptyTokenSet() {
        UUID userSub = UUID.randomUUID();
        String userTokensKey = "user_tokens:" + userSub;

        when(redisTemplate.opsForSet()).thenReturn(setOperations);
        when(setOperations.members(userTokensKey)).thenReturn(Collections.emptySet());

        authServiceImpl.revokeAllUserTokens(userSub);

        verify(setOperations, times(1)).members(userTokensKey);
        verify(redisTemplate, never()).delete(anyString());
        verify(redisTemplate, never()).delete(userTokensKey);
    }

    @Test
    void testRevokeAllUserTokens_WithNullTokenSet() {
        UUID userSub = UUID.randomUUID();
        String userTokensKey = "user_tokens:" + userSub;

        when(redisTemplate.opsForSet()).thenReturn(setOperations);
        when(setOperations.members(userTokensKey)).thenReturn(null);

        authServiceImpl.revokeAllUserTokens(userSub);

        verify(setOperations, times(1)).members(userTokensKey);
        verify(redisTemplate, never()).delete(anyString());
        verify(redisTemplate, never()).delete(userTokensKey);
    }

    @Test
    void testRevokeAllUserTokens_WithSingleToken() {
        UUID userSub = UUID.randomUUID();
        String userTokensKey = "user_tokens:" + userSub;
        Set<String> userJtis = Set.of("single-jti");

        when(redisTemplate.opsForSet()).thenReturn(setOperations);
        when(setOperations.members(userTokensKey)).thenReturn(userJtis);

        authServiceImpl.revokeAllUserTokens(userSub);

        verify(setOperations, times(1)).members(userTokensKey);
        verify(redisTemplate, times(1)).delete("refresh_token:single-jti");
        verify(redisTemplate, times(1)).delete(userTokensKey);
    }

    @Test
    void testLogout_WithNullRefreshToken() {
        String refreshToken = null;

        when(jwtServiceImpl.extractJti(refreshToken)).thenThrow(new IllegalArgumentException("Token cannot be null"));

        assertThrows(IllegalArgumentException.class, () -> authServiceImpl.logout(refreshToken));
    }

    @Test
    void testRevokeAllUserTokens_WithLargeTokenSet() {
        UUID userSub = UUID.randomUUID();
        String userTokensKey = "user_tokens:" + userSub;
        Set<String> userJtis = new HashSet<>();
        for (int i = 0; i < 100; i++) {
            userJtis.add("jti-" + i);
        }

        when(redisTemplate.opsForSet()).thenReturn(setOperations);
        when(setOperations.members(userTokensKey)).thenReturn(userJtis);

        authServiceImpl.revokeAllUserTokens(userSub);

        verify(setOperations, times(1)).members(userTokensKey);
        for (int i = 0; i < 100; i++) {
            verify(redisTemplate, times(1)).delete("refresh_token:jti-" + i);
        }
        verify(redisTemplate, times(1)).delete(userTokensKey);
    }

    @Test
    void testValidateToken_WithTokenContainingBearerPrefixAndSpaces() {
        String bearerToken = "Bearer   valid-jwt-token";
        String cleanToken = "  valid-jwt-token";
        String expectedUserId = "user-uuid-123";
        JwtUserInfo expectedResponse = new JwtUserInfo(expectedUserId,"ROLE_USER");
        when(jwtServiceImpl.validateTokenAndGetUserInfo(cleanToken))
                .thenReturn(expectedResponse);

        TokenValidationResponse result = authServiceImpl.validateToken(bearerToken);

        assertEquals(expectedUserId, result.getUserId());
        verify(jwtServiceImpl, times(1)).validateTokenAndGetUserInfo(cleanToken);
    }
}