package com.example.jointo;

import com.example.jointo.dto.AuthRequest;
import com.example.jointo.dto.JwtAuthenticationResponse;
import com.example.jointo.service.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationService authenticationService;

    @PostMapping("/signup")
    public ResponseEntity<JwtAuthenticationResponse> register(@RequestBody AuthRequest request) {
        var response = authenticationService.register(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/login")
    public ResponseEntity<JwtAuthenticationResponse> login(@RequestBody AuthRequest request) {
        var response = authenticationService.authenticate(request);
        return ResponseEntity.ok(response);
    }

    //Access in memory
    //Refresh in http only cookies
    @PostMapping("/refresh_token")
    public ResponseEntity<JwtAuthenticationResponse> refreshToken(
            HttpServletRequest request,
            HttpServletResponse response) {
        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        var refreshTokenResponse = authenticationService.refreshToken(authorizationHeader);
        if (refreshTokenResponse == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        return ResponseEntity.ok(refreshTokenResponse);
    }
}
