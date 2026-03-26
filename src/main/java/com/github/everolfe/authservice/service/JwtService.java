package com.github.everolfe.authservice.service;

import com.github.everolfe.authservice.entity.UserCredential;
import java.security.PublicKey;
import java.util.Map;

public interface JwtService {

    String KEY_ID = "main-rsa-key";

    String extractJti(String token);

    String extractSub(String token);

    boolean isTokenExpired(String token);

    Map<String, String> generateTokens(UserCredential userCredential);

    PublicKey getPublicKey();

    boolean isRefreshToken(String token);

    String validateTokenAndGetUserId(String token);
}
