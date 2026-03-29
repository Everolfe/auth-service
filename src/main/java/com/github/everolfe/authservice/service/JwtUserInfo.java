package com.github.everolfe.authservice.service;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@AllArgsConstructor
@Getter
@Setter
public class JwtUserInfo {
    private String userId;
    private String role;
}
