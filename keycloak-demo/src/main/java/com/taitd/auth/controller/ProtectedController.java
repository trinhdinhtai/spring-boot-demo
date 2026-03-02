package com.taitd.auth.controller;

import com.taitd.auth.dto.UserDto;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class ProtectedController {

    @GetMapping("/me")
    public ResponseEntity<UserDto> getCurrentUser(@AuthenticationPrincipal Jwt jwt) {
        UserDto userInfo = UserDto.builder()
            .sub(jwt.getSubject())
            .username(jwt.getClaimAsString("preferred_username"))
            .email(jwt.getClaimAsString("email"))
            .firstName(jwt.getClaimAsString("given_name"))
            .lastName(jwt.getClaimAsString("family_name"))
            .roles(jwt.getClaimAsStringList("roles"))
            .build();
        
        return ResponseEntity.ok(userInfo);
    }

    @GetMapping("/admin/dashboard")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Object> adminDashboard() {
        return ResponseEntity.ok(java.util.Map.of(
            "message", "Welcome to admin dashboard",
            "data", "Sensitive admin data here"
        ));
    }
}
