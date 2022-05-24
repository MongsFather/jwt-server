package com.mongsfather.jwt.dto;

import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class TokenDto {

    private String token;
    private String refreshToken;
    private Long tokenExpireTime;
}
