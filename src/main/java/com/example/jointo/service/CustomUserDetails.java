package com.example.jointo.service;

import com.example.jointo.entity.Role;
import com.example.jointo.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

@RequiredArgsConstructor
public class CustomUserDetails implements UserDetails {

    private final User user;

    public UUID getId() {
        return user.getId();
    }

    public List<String> getRoles() {
        return user.getRoles()
                .stream()
                .map(Role::name)
                .toList();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.getRoles()
                .stream()
                .map((role) -> new SimpleGrantedAuthority(role.name()))
                .toList();
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getEmail();
    }
}
