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

        String token = jwtUtil.generateToken(user.getUsername(), user.getRole());
        String refresh = jwtUtil.generateRefreshToken(user.getUsername(), user.getRole());

        return AuthResponse.builder()
                .token(token)
                .refreshToken(refresh)
                .username(user.getUsername())
                .role(user.getRole())
                .build();
    }

    public AuthResponse refreshToken(String refreshToken) {
        try {
            Claims claims = jwtUtil.validate(refreshToken);
            String username = claims.getSubject();
            Object rolesClaim = claims.get("roles");
            String role = null;
            if (rolesClaim instanceof List<?> list && !list.isEmpty()) {
                role = String.valueOf(list.get(0));
            }
            String newToken = jwtUtil.generateToken(username, role);
            String newRefresh = jwtUtil.generateRefreshToken(username, role);
            return AuthResponse.builder().token(newToken).refreshToken(newRefresh).username(username).role(role).build();
        } catch (Exception e) {
            throw new RuntimeException("Invalid refresh token");
        }
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
