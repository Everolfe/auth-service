package com.github.everolfe.authservice.dto.auth;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@NoArgsConstructor
@Builder
@Getter
@Setter
public class GetAuthDto {
    private String accessToken;
    private String refreshToken;
}
