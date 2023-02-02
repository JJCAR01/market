package com.cursoplatzi.market.web.controller;

import com.cursoplatzi.market.domain.dto.AuthenticationRequest;
import com.cursoplatzi.market.domain.dto.AuthenticationResponse;
import com.cursoplatzi.market.domain.service.MarketUserDetailsService;
import com.cursoplatzi.market.web.security.CustomAuthenticationProvider;
import com.cursoplatzi.market.web.security.JWTUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private JWTUtil jwtUtil;
    @Autowired
    private CustomAuthenticationProvider customAuthenticationProvider;
    @Autowired
    private MarketUserDetailsService marketUserDetailsService;
    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> createToken(@RequestBody AuthenticationRequest request) {
        try {

            customAuthenticationProvider.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
            UserDetails userDetails = marketUserDetailsService.loadUserByUsername(request.getUsername());

            String jwt = jwtUtil.generateToken(userDetails);
            AuthenticationResponse response = new AuthenticationResponse();
            response.setJwt(jwt);
            return new ResponseEntity<>(response, HttpStatus.OK);

        } catch (BadCredentialsException e) {
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }
}
