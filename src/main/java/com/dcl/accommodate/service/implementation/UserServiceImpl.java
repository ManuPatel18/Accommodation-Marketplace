package com.dcl.accommodate.service.implementation;

import com.dcl.accommodate.dto.request.UserLoginRequest;
import com.dcl.accommodate.dto.request.UserRegistrationRequest;
import com.dcl.accommodate.dto.response.AuthResponse;
import com.dcl.accommodate.enums.UserRole;
import com.dcl.accommodate.exceptions.UserAlreadyExistByEmailException;
import com.dcl.accommodate.model.User;
import com.dcl.accommodate.repository.UserRepository;
import com.dcl.accommodate.security.jwt.JwtService;
import com.dcl.accommodate.security.jwt.JwtType;
import com.dcl.accommodate.service.contracts.UserService;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;

import static com.dcl.accommodate.security.util.CurrentUser.getCurrentUserId;

@Service
@AllArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository repository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    @Override
    public void registerUser(UserRegistrationRequest registration) {
        if (repository.existsByEmail(registration.email())) {
            throw new UserAlreadyExistByEmailException("User already registered with such email ID");
        }

        var user = this.toUser(registration);
        user.setUserRole(UserRole.GUEST); // Default role
        user.setPassword(passwordEncoder.encode(user.getPassword()));

        repository.save(user);
    }

    @Override
    public AuthResponse loginUser(UserLoginRequest request) {
        var token = new UsernamePasswordAuthenticationToken(request.email(), request.password());
        var auth = authenticationManager.authenticate(token);

        if (!auth.isAuthenticated()) {
            throw new UsernameNotFoundException("Failed to authenticate username and password");
        }

        var user = repository.findByEmail(auth.getName())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        return grantTokens(user);
    }

    private AuthResponse grantTokens(User user) {
        Duration accessTtl = Duration.ofHours(1);
        Duration refreshTtl = Duration.ofDays(1);

        JwtService.TokenResult accessToken = generateAccessToken(user);
        JwtService.TokenResult refreshToken = generateRefreshToken(user);

        return new AuthResponse(
                user.getUserId().toString(),
                accessToken.token(),
                accessTtl.toSeconds(),
                refreshToken.token(),
                refreshTtl.toSeconds()
        );
    }

    @Override
    public AuthResponse refreshLogin() {
        Supplier<UsernameNotFoundException> userNotFound = () -> new UsernameNotFoundException("user name not found");
        UUID userId = getCurrentUserId().orElseThrow(userNotFound);

        User user = repository.findById(userId).orElseThrow(userNotFound);
        return grantTokens(user);
    }


    private JwtService.TokenResult generateAccessToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("email", user.getEmail());
        claims.put("role", user.getUserRole().name());

        var tokenConfig = new JwtService.TokenConfig(
                claims,
                user.getUserId().toString(),
                JwtType.ACCESS
        );

        return jwtService.generateToken(tokenConfig);

    }

    private JwtService.TokenResult generateRefreshToken(User user) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", "refresh");

        var tokenConfig = new JwtService.TokenConfig(
                claims,
                user.getUserId().toString(),
                JwtType.REFRESH
        );

        return jwtService.generateToken(tokenConfig);
    }


    private User toUser(UserRegistrationRequest registration) {
        return User.builder()
                .firstName(registration.firstName())
                .lastName(registration.lastName())
                .email(registration.email())
                .phoneNumber(registration.phoneNumber())
                .password(registration.password())
                .dateOfBirth(registration.dateOfBirth())
                .build();
    }
}