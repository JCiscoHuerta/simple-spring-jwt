package com.example.spring_jwt.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;

@Getter
public class AuthenticationResponse {
    @JsonProperty("access_token") //Solo para cambiarel nombre en el json
    private String token;
    @JsonProperty("refresh_token")
    private String refreshToken;

    public AuthenticationResponse(String token, String refreshToken) {
        this.token = token;
        this.refreshToken = refreshToken;
    }
}
