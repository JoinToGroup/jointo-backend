package com.example.jointo.service;

import com.example.jointo.dto.AuthRequest;
import com.example.jointo.dto.JwtAuthenticationResponse;
import com.example.jointo.entity.Role;
import com.example.jointo.entity.Token;
import com.example.jointo.entity.User;
import com.example.jointo.repository.TokenRepository;
import com.example.jointo.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.UUID;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final CustomUserDetailsService customUserDetailsService;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final TokenRepository tokenRepository;

    public JwtAuthenticationResponse register(AuthRequest request) {
        var user = User.builder()
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .roles(new HashSet<>(List.of(Role.ROLE_USER)))
                .build();

        var savedUser = userRepository.save(user);
        log.info("Saved user: {}", savedUser);

        var userDetails = new CustomUserDetails(user);
        var accessToken = jwtService.generateAccessToken(userDetails);
        var refreshToken = jwtService.generateRefreshToken(userDetails); // To login after registration
        return new JwtAuthenticationResponse(accessToken, refreshToken);
    }

    public JwtAuthenticationResponse authenticate(AuthRequest request) {
        var email = request.email();

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, request.password())
        );
        User user = userRepository.findByEmail(email).orElseThrow(() -> new RuntimeException("user not found"));
        var userDetails = (CustomUserDetails) customUserDetailsService.loadUserByUsername(email);

        String accessToken = jwtService.generateAccessToken(userDetails);
        String refreshToken = jwtService.generateRefreshToken(userDetails);

        revokeAllToken(userDetails.getId());

        saveUserToken(accessToken, refreshToken, user);

        return new JwtAuthenticationResponse(accessToken, refreshToken);
    }

    public JwtAuthenticationResponse refreshToken(String authorizationHeader) {

        String token = authorizationHeader.substring(7);
        String username = jwtService.extractUsername(token);

        User user = userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("No user found"));
        var userDetails = (CustomUserDetails) customUserDetailsService.loadUserByUsername(username);

        if (jwtService.isValidRefresh(token, userDetails)) {

            String accessToken = jwtService.generateAccessToken(userDetails);
            String refreshToken = jwtService.generateRefreshToken(userDetails);

            revokeAllToken(userDetails.getId());

            saveUserToken(accessToken, refreshToken, user);

            return new JwtAuthenticationResponse(accessToken, refreshToken);

        }
        return null;
    }

    private void saveUserToken(String accessToken, String refreshToken, User user) {

        Token token = Token.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .loggedOut(false)
                .user(user)
                .build();

        tokenRepository.save(token);
    }

    private void revokeAllToken(UUID userId) {
        List<Token> validTokens = tokenRepository.findAllTokensByUserId(userId);
        validTokens.forEach(token -> token.setLoggedOut(true));

        tokenRepository.saveAll(validTokens);
    }
}
