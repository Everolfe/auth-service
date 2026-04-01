package com.github.everolfe.authservice.integration;

import com.github.everolfe.authservice.dao.OutboxRepository;
import com.github.everolfe.authservice.dao.UserCredentialRepository;
import com.github.everolfe.authservice.dto.GetRefreshTokenDto;
import com.github.everolfe.authservice.dto.auth.CreateAuthDto;
import com.github.everolfe.authservice.dto.auth.GetAuthDto;
import com.github.everolfe.authservice.entity.Outbox;
import com.github.everolfe.authservice.entity.OutboxStatus;
import com.github.everolfe.authservice.entity.UserCredential;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import java.time.Duration;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.time.LocalDate;
import java.util.Map;
import java.util.Optional;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class AuthIntegrationTest extends BaseIntegrationTest {

    private static final String AUTH_PATH = "/api/auth";
    private static final String USER_SERVICE_PATH = "/api/users/internal/register";

    @RegisterExtension
    static WireMockExtension wireMockServer = WireMockExtension.newInstance()
            .options(WireMockConfiguration.wireMockConfig().dynamicPort())
            .build();

    @Autowired
    private UserCredentialRepository userCredentialRepository;

    @Autowired
    private OutboxRepository outboxRepository;

    @LocalServerPort
    private int port;

    @DynamicPropertySource
    static void overrideProperties(DynamicPropertyRegistry registry) {
        registry.add("app.userservice.url", () -> "http://localhost:" + wireMockServer.getPort() + "/api/users/internal/register");
    }

    @BeforeEach
    void setUp() {
        RestAssured.port = port;
        RestAssured.defaultParser = io.restassured.parsing.Parser.JSON;
        wireMockServer.resetAll();
    }

    @AfterEach
    void cleanDatabase() {
        outboxRepository.deleteAll();
        userCredentialRepository.deleteAll();
    }

    @Test
    void register_ShouldReturnSuccess_WhenDataIsValid() {
        wireMockServer.stubFor(post(urlEqualTo(USER_SERVICE_PATH))
                .willReturn(aResponse()
                        .withStatus(HttpStatus.OK.value())
                        .withBody("User created successfully")));

        CreateAuthDto createAuthDto = createValidAuthDto();

        String response = given()
                .contentType(ContentType.JSON)
                .body(createAuthDto)
                .when()
                .post(AUTH_PATH + "/register")
                .then()
                .statusCode(HttpStatus.OK.value())
                .extract()
                .asString();

        assertThat(response).isEqualTo("User registered successfully");

        UserCredential savedUser = userCredentialRepository
                .findByEmail(createAuthDto.getEmail())
                .orElse(null);

        assertThat(savedUser).isNotNull();
        assertThat(savedUser.getEmail()).isEqualTo(createAuthDto.getEmail());
        assertThat(savedUser.getRole()).isEqualTo(com.github.everolfe.authservice.entity.Role.ROLE_USER);
        assertThat(savedUser.getSub()).isNotNull();

        Optional<Outbox> outbox = outboxRepository.findAll().stream()
                .filter(o -> o.getPayload().contains(createAuthDto.getEmail()))
                .findFirst();

        assertThat(outbox).isPresent();
        assertThat(outbox.get().getStatus()).isEqualTo(OutboxStatus.PENDING);

    }

    @Test
    void register_ShouldReturnSuccess_EvenWhenUserServiceIsDown() {
        wireMockServer.stubFor(post(urlEqualTo(USER_SERVICE_PATH))
                .willReturn(aResponse()
                        .withStatus(HttpStatus.INTERNAL_SERVER_ERROR.value())
                        .withBody("User service error")));

        CreateAuthDto createAuthDto = createValidAuthDto();

        given()
                .contentType(ContentType.JSON)
                .body(createAuthDto)
                .when()
                .post(AUTH_PATH + "/register")
                .then()
                .statusCode(HttpStatus.OK.value());

        UserCredential savedUser = userCredentialRepository
                .findByEmail(createAuthDto.getEmail())
                .orElse(null);

        assertThat(savedUser).isNotNull();

        Optional<Outbox> outbox = outboxRepository.findAll().stream()
                .filter(o -> o.getPayload().contains(createAuthDto.getEmail()))
                .findFirst();

        assertThat(outbox).isPresent();
        assertThat(outbox.get().getStatus()).isEqualTo(OutboxStatus.PENDING);
    }

    @Test
    void login_ShouldReturnTokens_WhenCredentialsAreValid() {
        CreateAuthDto createAuthDto = createValidAuthDto();

        given()
                .contentType(ContentType.JSON)
                .body(createAuthDto)
                .when()
                .post(AUTH_PATH + "/register")
                .then()
                .statusCode(HttpStatus.OK.value());

        GetAuthDto tokens = given()
                .contentType(ContentType.JSON)
                .body(createAuthDto)
                .when()
                .post(AUTH_PATH + "/login")
                .then()
                .statusCode(HttpStatus.OK.value())
                .extract()
                .as(GetAuthDto.class);

        assertThat(tokens).isNotNull();
        assertThat(tokens.getAccessToken()).isNotNull();
        assertThat(tokens.getRefreshToken()).isNotNull();
        assertThat(tokens.getAccessToken()).isNotEqualTo(tokens.getRefreshToken());
    }

    @Test
    void login_ShouldReturnUnauthorized_WhenCredentialsAreInvalid() {
        CreateAuthDto createAuthDto = createValidAuthDto();
        createAuthDto.setPassword("wrongpassword");

        given()
                .contentType(ContentType.JSON)
                .body(createAuthDto)
                .when()
                .post(AUTH_PATH + "/login")
                .then()
                .statusCode(HttpStatus.UNAUTHORIZED.value());
    }

    @Test
    void refresh_ShouldReturnNewTokens_WhenRefreshTokenIsValid() {
        CreateAuthDto createAuthDto = createValidAuthDto();

        given()
                .contentType(ContentType.JSON)
                .body(createAuthDto)
                .when()
                .post(AUTH_PATH + "/register")
                .then()
                .statusCode(HttpStatus.OK.value());

        GetAuthDto loginResponse = given()
                .contentType(ContentType.JSON)
                .body(createAuthDto)
                .when()
                .post(AUTH_PATH + "/login")
                .then()
                .statusCode(HttpStatus.OK.value())
                .extract()
                .as(GetAuthDto.class);

        Awaitility.await()
                .atMost(Duration.ofSeconds(5))
                .pollInterval(Duration.ofMillis(500))
                .until(() -> {
                    GetRefreshTokenDto refreshTokenDto = new GetRefreshTokenDto();
                    refreshTokenDto.setRefreshToken(loginResponse.getRefreshToken());

                    GetAuthDto tokens = given()
                            .contentType(ContentType.JSON)
                            .body(refreshTokenDto)
                            .when()
                            .post(AUTH_PATH + "/refresh")
                            .then()
                            .statusCode(HttpStatus.OK.value())
                            .extract()
                            .as(GetAuthDto.class);

                    return !tokens.getAccessToken().equals(loginResponse.getAccessToken());
                });
    }


    @Test
    void refresh_ShouldReturnUnauthorized_WhenRefreshTokenIsInvalid() {
        GetRefreshTokenDto refreshTokenDto = new GetRefreshTokenDto();
        refreshTokenDto.setRefreshToken("invalid-token");

        given()
                .contentType(ContentType.JSON)
                .body(refreshTokenDto)
                .when()
                .post(AUTH_PATH + "/refresh")
                .then()
                .statusCode(HttpStatus.UNAUTHORIZED.value());
    }

    @Test
    void wellKnownJwks_ShouldReturnJwkSet() {
        Map<String, Object> jwkSet = given()
                .when()
                .get(AUTH_PATH + "/well-known/jwks.json")
                .then()
                .statusCode(HttpStatus.OK.value())
                .extract()
                .as(Map.class);

        assertThat(jwkSet)
                .isNotNull()
                .containsKey("keys");

        Object keys = jwkSet.get("keys");
        assertThat(keys).isInstanceOf(java.util.List.class);

        java.util.List<?> keyList = (java.util.List<?>) keys;
        assertThat(keyList).isNotEmpty();

        Map<String, Object> firstKey = (Map<String, Object>) keyList.get(0);
        assertThat(firstKey)
                .containsKey("kty")
                .containsEntry("kty", "RSA")
                .containsKey("kid")
                .containsEntry("kid", "main-rsa-key");
    }

    @Test
    void register_ShouldSaveUserEvenIfUserServiceIsDown() {
        wireMockServer.stubFor(post(urlEqualTo(USER_SERVICE_PATH))
                .willReturn(aResponse()
                        .withStatus(HttpStatus.INTERNAL_SERVER_ERROR.value())
                        .withBody("User service error")));

        CreateAuthDto createAuthDto = createValidAuthDto();

        given()
                .contentType(ContentType.JSON)
                .body(createAuthDto)
                .when()
                .post(AUTH_PATH + "/register")
                .then()
                .statusCode(HttpStatus.OK.value());

        Optional<UserCredential> savedUser = userCredentialRepository
                .findByEmail(createAuthDto.getEmail());

        assertThat(savedUser).isPresent();

        Optional<Outbox> outbox = outboxRepository.findAll().stream()
                .filter(o -> o.getPayload().contains(createAuthDto.getEmail()))
                .findFirst();

        assertThat(outbox).isPresent();
    }

    private CreateAuthDto createValidAuthDto() {
        CreateAuthDto dto = new CreateAuthDto();
        dto.setEmail("test.user." + System.currentTimeMillis() + "@example.com");
        dto.setPassword("Password123!");
        dto.setName("Test");
        dto.setSurname("User");
        dto.setBirthDate(LocalDate.of(1990, 1, 1));
        return dto;
    }
}