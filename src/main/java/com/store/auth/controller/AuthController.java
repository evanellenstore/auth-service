package com.store.auth.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.store.auth.dto.AuthResponse;
import com.store.auth.dto.AuthValidationResponse;
import com.store.auth.dto.LoginRequest;
import com.store.auth.service.AuthService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
@Slf4j
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService service;

    @PostMapping("/login")
    public AuthResponse login(@RequestBody LoginRequest request) {
        return service.login(request);
    }

    @PostMapping("/refresh")
    public AuthResponse refresh(@RequestBody com.store.auth.dto.RefreshRequest req) {
        return service.refreshToken(req.getRefreshToken());
    }

    @PostMapping("/validate")
    public AuthValidationResponse validate(@RequestHeader("Authorization") String token) {
        AuthValidationResponse res = service.validateToken(token.replace("Bearer ", ""));

        log.info("Auth validation response: {}", res);
        return res;
    }


}
