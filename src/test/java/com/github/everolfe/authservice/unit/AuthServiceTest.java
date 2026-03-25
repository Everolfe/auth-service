package com.github.everolfe.authservice.unit;

import com.github.everolfe.authservice.dao.UserCredentialRepository;
import com.github.everolfe.authservice.dto.CreateProfileDto;
import com.github.everolfe.authservice.dto.GetRefreshTokenDto;
import com.github.everolfe.authservice.dto.auth.CreateAuthDto;
import com.github.everolfe.authservice.dto.auth.GetAuthDto;
import com.github.everolfe.authservice.entity.Role;
import com.github.everolfe.authservice.entity.UserCredential;
import com.github.everolfe.authservice.service.AuthService;
import com.github.everolfe.authservice.service.JwtService;
import io.jsonwebtoken.JwtException;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDate;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

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
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @Mock
    private RestTemplate restTemplate;

    @InjectMocks
    private AuthService authService;

    @BeforeEach
    void setUp(){
        ReflectionTestUtils.setField(authService, "userServiceUrl", "http://localhost:8081/api/users/internal/register");
    }

    @Test
    void testRegisterSuccess() {
        CreateAuthDto createAuthDto = new CreateAuthDto();
        createAuthDto.setEmail("test@example.com");
        createAuthDto.setPassword("password123");
        createAuthDto.setName("John");
        createAuthDto.setSurname("Doe");
        createAuthDto.setBirthDate(LocalDate.of(1990, 1, 1));

        String encodedPassword = "encodedPassword";

        when(passwordEncoder.encode(createAuthDto.getPassword())).thenReturn(encodedPassword);
        when(restTemplate.postForObject(anyString(), any(CreateProfileDto.class), eq(String.class)))
                .thenReturn("success");
        when(userCredentialRepository.save(any(UserCredential.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        boolean result = authService.register(createAuthDto);

        assertTrue(result);
        verify(passwordEncoder, times(1)).encode("password123");
        verify(restTemplate, times(1)).postForObject(anyString(), any(CreateProfileDto.class), eq(String.class));
        verify(userCredentialRepository, times(1)).save(any(UserCredential.class));
    }

    @Test
    void testRegisterWithUserServiceFailure() {
        CreateAuthDto createAuthDto = new CreateAuthDto();
        createAuthDto.setEmail("test@example.com");
        createAuthDto.setPassword("password123");
        createAuthDto.setName("John");
        createAuthDto.setSurname("Doe");

        when(passwordEncoder.encode(createAuthDto.getPassword())).thenReturn("encodedPassword");
        when(restTemplate.postForObject(anyString(), any(CreateProfileDto.class), eq(String.class)))
                .thenThrow(new RestClientException("User service unavailable"));

        boolean result = authService.register(createAuthDto);

        assertFalse(result);
        verify(passwordEncoder, times(1)).encode(createAuthDto.getPassword());
        verify(restTemplate, times(1)).postForObject(anyString(), any(CreateProfileDto.class), eq(String.class));
        verify(userCredentialRepository, never()).save(any(UserCredential.class));
    }

    @Test
    void testRegisterWithExceptionThrown() {
        CreateAuthDto createAuthDto = new CreateAuthDto();
        createAuthDto.setEmail("test@example.com");
        createAuthDto.setPassword("password123");

        when(passwordEncoder.encode(createAuthDto.getPassword())).thenReturn("encodedPassword");
        when(restTemplate.postForObject(anyString(), any(CreateProfileDto.class), eq(String.class)))
                .thenThrow(new RuntimeException("Network error"));

        boolean result = authService.register(createAuthDto);

        assertFalse(result);
        verify(userCredentialRepository, never()).save(any(UserCredential.class));
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

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getPrincipal()).thenReturn(userCredential);
        when(jwtService.generateTokens(userCredential)).thenReturn(tokens);

        GetAuthDto result = authService.login(createAuthDto);

        assertNotNull(result);
        assertEquals("access-token-value", result.getAccessToken());
        assertEquals("refresh-token-value", result.getRefreshToken());

        verify(authenticationManager, times(1)).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(jwtService, times(1)).generateTokens(userCredential);
    }

    @Test
    void testLoginWithInvalidCredentials() {
        CreateAuthDto createAuthDto = new CreateAuthDto();
        createAuthDto.setEmail("test@example.com");
        createAuthDto.setPassword("wrongpassword");

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Invalid credentials"));

        assertThrows(BadCredentialsException.class, () -> authService.login(createAuthDto));

        verify(authenticationManager, times(1)).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(jwtService, never()).generateTokens(any());
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

        assertThrows(BadCredentialsException.class, () -> authService.login(createAuthDto));

        verify(jwtService, never()).generateTokens(any());
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

        when(jwtService.isTokenExpired(refreshTokenValue)).thenReturn(false);
        when(jwtService.extractSub(refreshTokenValue)).thenReturn(sub.toString());
        when(userCredentialRepository.findBySub(sub)).thenReturn(Optional.of(userCredential));
        when(jwtService.generateTokens(userCredential)).thenReturn(tokens);

        GetAuthDto result = authService.refreshToken(refreshTokenDto);

        assertNotNull(result);
        assertEquals("new-access-token", result.getAccessToken());
        assertEquals("new-refresh-token", result.getRefreshToken());

        verify(jwtService, times(1)).isTokenExpired(refreshTokenValue);
        verify(jwtService, times(1)).extractSub(refreshTokenValue);
        verify(userCredentialRepository, times(1)).findBySub(sub);
        verify(jwtService, times(1)).generateTokens(userCredential);
    }

    @Test
    void testRefreshTokenWithExpiredToken() {
        GetRefreshTokenDto refreshTokenDto = new GetRefreshTokenDto();
        String refreshTokenValue = "expired-refresh-token";
        refreshTokenDto.setRefreshToken(refreshTokenValue);

        when(jwtService.isTokenExpired(refreshTokenValue)).thenReturn(true);

        assertThrows(JwtException.class, () -> authService.refreshToken(refreshTokenDto));

        verify(jwtService, times(1)).isTokenExpired(refreshTokenValue);
        verify(jwtService, never()).extractSub(any());
        verify(userCredentialRepository, never()).findBySub(any());
    }

    @Test
    void testRefreshTokenWithInvalidSubject() {
        GetRefreshTokenDto refreshTokenDto = new GetRefreshTokenDto();
        String refreshTokenValue = "valid-refresh-token";
        refreshTokenDto.setRefreshToken(refreshTokenValue);

        UUID sub = UUID.randomUUID();

        when(jwtService.isTokenExpired(refreshTokenValue)).thenReturn(false);
        when(jwtService.extractSub(refreshTokenValue)).thenReturn(sub.toString());
        when(userCredentialRepository.findBySub(sub)).thenReturn(Optional.empty());

        assertThrows(BadCredentialsException.class, () -> authService.refreshToken(refreshTokenDto));

        verify(jwtService, times(1)).isTokenExpired(refreshTokenValue);
        verify(jwtService, times(1)).extractSub(refreshTokenValue);
        verify(userCredentialRepository, times(1)).findBySub(sub);
        verify(jwtService, never()).generateTokens(any());
    }

    @Test
    void testRefreshTokenWithMalformedSub() {
        GetRefreshTokenDto refreshTokenDto = new GetRefreshTokenDto();
        String refreshTokenValue = "valid-refresh-token";
        refreshTokenDto.setRefreshToken(refreshTokenValue);

        when(jwtService.isTokenExpired(refreshTokenValue)).thenReturn(false);
        when(jwtService.extractSub(refreshTokenValue)).thenReturn("not-a-valid-uuid");

        assertThrows(IllegalArgumentException.class, () -> authService.refreshToken(refreshTokenDto));

        verify(jwtService, times(1)).isTokenExpired(refreshTokenValue);
        verify(jwtService, times(1)).extractSub(refreshTokenValue);
        verify(userCredentialRepository, never()).findBySub(any());
    }

    @Test
    void testGetJwtSetSuccess() {

        RSAPublicKey mockPublicKey = mock(RSAPublicKey.class);
        when(mockPublicKey.getModulus()).thenReturn(new java.math.BigInteger("123456789"));
        when(mockPublicKey.getPublicExponent()).thenReturn(java.math.BigInteger.valueOf(65537));
        when(jwtService.getPublicKey()).thenReturn(mockPublicKey);

        Map<String, Object> result = authService.getJwtSet();

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

        verify(jwtService, atLeastOnce()).getPublicKey();
    }


    @Test
    void testRegisterCreatesProfileDtoWithAllFields() {

        CreateAuthDto createAuthDto = new CreateAuthDto();
        createAuthDto.setEmail("test@example.com");
        createAuthDto.setPassword("password123");
        createAuthDto.setName("John");
        createAuthDto.setSurname("Doe");
        createAuthDto.setBirthDate(LocalDate.of(1990, 5, 15));

        when(passwordEncoder.encode(createAuthDto.getPassword())).thenReturn("encodedPassword");
        when(restTemplate.postForObject(anyString(), any(CreateProfileDto.class), eq(String.class)))
                .thenReturn("success");

        ArgumentCaptor<CreateProfileDto> profileDtoCaptor = ArgumentCaptor.forClass(CreateProfileDto.class);
        ArgumentCaptor<String> urlCaptor = ArgumentCaptor.forClass(String.class);

        authService.register(createAuthDto);

        verify(restTemplate).postForObject(urlCaptor.capture(), profileDtoCaptor.capture(), eq(String.class));

        assertEquals("http://localhost:8081/api/users/internal/register", urlCaptor.getValue());

        CreateProfileDto capturedProfileDto = profileDtoCaptor.getValue();
        assertNotNull(capturedProfileDto.getSub());
        assertEquals("John", capturedProfileDto.getName());
        assertEquals("Doe", capturedProfileDto.getSurname());
        assertEquals("test@example.com", capturedProfileDto.getEmail());
        assertEquals(LocalDate.of(1990, 5, 15), capturedProfileDto.getBirthDate());
    }

    @Test
    void testRegisterCreatesProfileDtoWithoutOptionalFields() {
        CreateAuthDto createAuthDto = new CreateAuthDto();
        createAuthDto.setEmail("test@example.com");
        createAuthDto.setPassword("password123");

        when(passwordEncoder.encode(createAuthDto.getPassword())).thenReturn("encodedPassword");
        when(restTemplate.postForObject(anyString(), any(CreateProfileDto.class), eq(String.class)))
                .thenReturn("success");

        ArgumentCaptor<CreateProfileDto> profileDtoCaptor = ArgumentCaptor.forClass(CreateProfileDto.class);

        authService.register(createAuthDto);

        verify(restTemplate).postForObject(anyString(), profileDtoCaptor.capture(), eq(String.class));

        CreateProfileDto capturedProfileDto = profileDtoCaptor.getValue();
        assertNotNull(capturedProfileDto.getSub());
        assertEquals("test@example.com", capturedProfileDto.getEmail());
        assertNull(capturedProfileDto.getName());
        assertNull(capturedProfileDto.getSurname());
        assertNull(capturedProfileDto.getBirthDate());
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

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getPrincipal()).thenReturn(userCredential);
        when(jwtService.generateTokens(userCredential)).thenReturn(tokens);


        authService.login(createAuthDto);

        verify(authenticationManager).authenticate(argThat(token -> {
            UsernamePasswordAuthenticationToken authToken = (UsernamePasswordAuthenticationToken) token;
            return "test@example.com".equals(authToken.getPrincipal()) &&
                    "password123".equals(authToken.getCredentials());
        }));
    }

    @Test
    void testRegisterSavesUserWithCorrectRoleAndSub() {
        CreateAuthDto createAuthDto = new CreateAuthDto();
        createAuthDto.setEmail("test@example.com");
        createAuthDto.setPassword("password123");
        createAuthDto.setName("John");
        createAuthDto.setSurname("Doe");

        when(passwordEncoder.encode(createAuthDto.getPassword())).thenReturn("encodedPassword");
        when(restTemplate.postForObject(anyString(), any(CreateProfileDto.class), eq(String.class)))
                .thenReturn("success");

        ArgumentCaptor<UserCredential> userCredentialCaptor = ArgumentCaptor.forClass(UserCredential.class);

        authService.register(createAuthDto);

        verify(userCredentialRepository).save(userCredentialCaptor.capture());

        UserCredential savedCredential = userCredentialCaptor.getValue();
        assertEquals(Role.ROLE_USER, savedCredential.getRole());
        assertEquals("test@example.com", savedCredential.getEmail());
        assertEquals("encodedPassword", savedCredential.getPassword());
        assertNotNull(savedCredential.getSub());
    }

    @Test
    void testRegisterGeneratesUniqueSubForEachUser() {
        CreateAuthDto createAuthDto1 = new CreateAuthDto();
        createAuthDto1.setEmail("user1@example.com");
        createAuthDto1.setPassword("password123");

        CreateAuthDto createAuthDto2 = new CreateAuthDto();
        createAuthDto2.setEmail("user2@example.com");
        createAuthDto2.setPassword("password456");

        when(passwordEncoder.encode(anyString())).thenReturn("encodedPassword");
        when(restTemplate.postForObject(anyString(), any(CreateProfileDto.class), eq(String.class)))
                .thenReturn("success");

        ArgumentCaptor<UserCredential> userCaptor1 = ArgumentCaptor.forClass(UserCredential.class);

        authService.register(createAuthDto1);
        authService.register(createAuthDto2);

        verify(userCredentialRepository, times(2)).save(userCaptor1.capture());

        UserCredential user1 = userCaptor1.getAllValues().get(0);
        UserCredential user2 = userCaptor1.getAllValues().get(1);

        assertNotEquals(user1.getSub(), user2.getSub(), "Sub values should be unique");
    }
}