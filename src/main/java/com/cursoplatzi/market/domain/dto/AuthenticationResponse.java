package com.cursoplatzi.market.domain.dto;

public class AuthenticationResponse {

    private String jwt;

    public AuthenticationResponse() {
        this.jwt = jwt;
    }

    public String getJwt() {
        return jwt;
    }

    public void setJwt(String jwt) {
        this.jwt = jwt;
    }
}
