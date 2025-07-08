package com.example.jointo.configuration;

import com.example.jointo.service.CustomLogoutHandler;
import com.example.jointo.service.CustomUserDetailsService;
import com.example.jointo.service.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig {


    @Value("${cors.allowed-origins}")
    private String[] allowedOrigins;

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final CustomLogoutHandler customLogoutHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   CustomUserDetailsService customUserDetailsService) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(request -> request
                        .requestMatchers("/api/v1/auth/**").permitAll()
                        .requestMatchers("/swagger-ui/**", "/swagger-resources/*", "/v3/api-docs/**").permitAll()
                        .requestMatchers("/public/**").permitAll()
                        .anyRequest().authenticated())
                // disable default session management, as we use jwt validation for every request
                .sessionManagement(manager -> manager.sessionCreationPolicy(STATELESS))
                .authenticationProvider(authenticationProvider(customUserDetailsService))
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .logout(configurer -> {
                    configurer.logoutUrl("/api/v1/auth//logout");
                    configurer.addLogoutHandler(customLogoutHandler);
                    configurer.logoutSuccessHandler((request, response, authentication) ->
                            SecurityContextHolder.clearContext());
                });

        return http.build();
    }

    /**
     * List of allowed origins for CORS configuration.
     * <p>
     * These origins are explicitly permitted to make cross-origin HTTP requests
     * to the backend API. Used in the CORS policy setup via {@code CorsConfiguration}.
     * <ul>
     *   <li>{@code http://localhost:3000} — local development frontend (React, Angular, etc.)</li>
     *   <li>{@code https://myfrontend.com} — production deployment of the frontend</li>
     *   <li>{@code https://*.trustedpartner.com} — allows any subdomain of a trusted partner (requires use of origin patterns)</li>
     * </ul>
     *
     * <p><strong>Note:</strong> During development or testing, a wildcard {@code "*"} may be used
     * via {@code setAllowedOriginPatterns(List.of("*"))} to permit all origins.
     * However, this must be avoided in production if {@code setAllowCredentials(true)} is used,
     * as the CORS specification forbids wildcard origins with credentials.
     */
    @Bean
    UrlBasedCorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(List.of(allowedOrigins));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        configuration.setAllowedHeaders(List.of("Authorization", "Cache-Control", "Content-Type", "ngrok-skip-browser-warning"));
        configuration.setAllowCredentials(true);
        configuration.setExposedHeaders(List.of("Set-Cookie"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider(CustomUserDetailsService customUserDetailsService) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(customUserDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
