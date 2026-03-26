package com.github.everolfe.authservice.service;

import com.github.everolfe.authservice.dto.GetRefreshTokenDto;
import com.github.everolfe.authservice.dto.auth.CreateAuthDto;
import com.github.everolfe.authservice.dto.auth.GetAuthDto;
import java.util.Map;
import java.util.UUID;

public interface AuthService {
    boolean register(CreateAuthDto createAuthDto);

    GetAuthDto login(CreateAuthDto createAuthDto);

    GetAuthDto refreshToken(GetRefreshTokenDto refreshTokenDto);

    Map<String, Object> getJwtSet();

    void logout(String refreshToken);

    void revokeAllUserTokens(UUID userSub);

    String validateToken(String token);
}
