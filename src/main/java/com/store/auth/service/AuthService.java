package com.store.auth.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Service;

import com.store.auth.client.UserClient;
import com.store.auth.dto.AuthResponse;
import com.store.auth.dto.AuthValidationResponse;
import com.store.auth.dto.LoginRequest;
import com.store.auth.dto.UserDto;
import com.store.auth.util.JwtUtil;

import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserClient userClient;
    private final JwtUtil jwtUtil;

    public AuthResponse login(LoginRequest request) {

        UserDto user = userClient.getByUsername(request.getUsername());

        if (user == null || !user.getPassword().equals(request.getPassword())) {
            throw new RuntimeException("Invalid credentials");
        }

        if (!user.getActive()) {
            throw new RuntimeException("User inactive");
        }

        String token = jwtUtil.generateToken(
                user.getUsername(),
                user.getRole());

        return AuthResponse.builder()
                .token(token)
                .username(user.getUsername())
                .role(user.getRole())
                .build();
    }

    public AuthValidationResponse validateToken(String token) {
        try {
            Claims claims = jwtUtil.validate(token);

            Object rolesClaim = claims.get("roles");
            Object roleClaim = claims.get("role");

            List<String> roles = new ArrayList<>();

            if (rolesClaim instanceof List<?> list) {
                roles = list.stream().map(String::valueOf).toList();
            } else if (rolesClaim instanceof String r) {
                roles.add(r);
            } else if (roleClaim != null) {
                roles.add(String.valueOf(roleClaim));
            }

            return new AuthValidationResponse(
                    true,
                    claims.getSubject(),
                    roles);

        } catch (Exception e) {
            return new AuthValidationResponse(false, null, null);
        }
    }
}
