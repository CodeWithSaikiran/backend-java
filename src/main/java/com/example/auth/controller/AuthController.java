package com.example.auth.controller;

import com.example.auth.dto.AuthRequest;
import com.example.auth.dto.AuthResponse;
import com.example.auth.dto.SignUpRequest;
import com.example.auth.entity.User;
import com.example.auth.repository.UserRepository;
import com.example.auth.security.JwtTokenProvider;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider tokenProvider;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    
    @Value("${app.auth.brute-force-max-attempts:5}")
    private int maxAttempts;
    
    @Value("${app.auth.brute-force-lock-duration-minutes:15}")
    private int lockDurationMinutes;
    
    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody AuthRequest loginRequest) {
        Optional<User> userOpt = userRepository.findByUsername(loginRequest.getUsername());
        
        // Check if user exists
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Invalid username or password", "code", "INVALID_CREDENTIALS"));
        }
        
        User user = userOpt.get();
        
        // Check if account is locked due to failed attempts
        if (user.getAccountLocked()) {
            long minutesLocked = java.time.temporal.ChronoUnit.MINUTES.between(user.getLockTime(), LocalDateTime.now());
            if (minutesLocked < lockDurationMinutes) {
                long remainingMinutes = lockDurationMinutes - minutesLocked;
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                        "error", "Account locked due to too many failed login attempts",
                        "code", "ACCOUNT_LOCKED",
                        "remainingMinutes", remainingMinutes
                    ));
            } else {
                // Unlock the account if lock duration has passed
                userRepository.unlockAccount(loginRequest.getUsername());
                user.setAccountLocked(false);
                user.setFailedAttempts(0);
            }
        }
        
        // Check if user is active
        if (!user.getIsActive()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Account is disabled", "code", "ACCOUNT_DISABLED"));
        }
        
        try {
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    loginRequest.getUsername(),
                    loginRequest.getPassword()
                )
            );
            
            SecurityContextHolder.getContext().setAuthentication(authentication);
            String accessToken = tokenProvider.generateToken(authentication);
            String refreshToken = tokenProvider.generateRefreshToken(loginRequest.getUsername());
            
            userRepository.resetFailedAttemptsAndUpdateLogin(loginRequest.getUsername());
            
            Map<String, Object> response = new HashMap<>();
            response.put("token", accessToken);
            response.put("refreshToken", refreshToken);
            response.put("username", user.getUsername());
            response.put("email", user.getEmail());
            response.put("message", "Login successful");
            
            return ResponseEntity.ok(response);
        } catch (BadCredentialsException e) {
            // Increment failed attempts
            userRepository.incrementFailedAttempts(loginRequest.getUsername());
            User updatedUser = userRepository.findByUsername(loginRequest.getUsername()).get();
            
            // Lock account if max attempts exceeded
            if (updatedUser.getFailedAttempts() >= maxAttempts) {
                userRepository.lockAccount(loginRequest.getUsername(), LocalDateTime.now());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                        "error", "Account locked due to too many failed login attempts",
                        "code", "ACCOUNT_LOCKED",
                        "attemptsRemaining", 0
                    ));
            }
            
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of(
                    "error", "Invalid username or password",
                    "code", "INVALID_CREDENTIALS",
                    "attemptsRemaining", maxAttempts - updatedUser.getFailedAttempts()
                ));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "An unexpected error occurred", "code", "INTERNAL_ERROR"));
        }
    }
    
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");
        
        if (refreshToken == null || refreshToken.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of("error", "Refresh token is required", "code", "MISSING_REFRESH_TOKEN"));
        }
        
        try {
            // Check if refresh token is valid (even if expired, just check signature)
            if (!tokenProvider.validateToken(refreshToken)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid refresh token", "code", "INVALID_REFRESH_TOKEN"));
            }
            
            String username = tokenProvider.getUsernameFromToken(refreshToken);
            Optional<User> userOpt = userRepository.findByUsername(username);
            
            if (userOpt.isEmpty() || !userOpt.get().getIsActive()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "User not found or inactive", "code", "USER_INVALID"));
            }
            
            String newAccessToken = tokenProvider.generateTokenFromUsername(username);
            String newRefreshToken = tokenProvider.generateRefreshToken(username);
            
            Map<String, Object> response = new HashMap<>();
            response.put("token", newAccessToken);
            response.put("refreshToken", newRefreshToken);
            response.put("message", "Token refreshed successfully");
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Token refresh failed", "code", "REFRESH_FAILED"));
        }
    }
    
    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity.badRequest()
                .body(Map.of("error", "Username is already taken", "code", "USERNAME_TAKEN"));
        }
        
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity.badRequest()
                .body(Map.of("error", "Email is already in use", "code", "EMAIL_IN_USE"));
        }
        
        User user = new User();
        user.setUsername(signUpRequest.getUsername());
        user.setEmail(signUpRequest.getEmail());
        user.setPasswordHash(passwordEncoder.encode(signUpRequest.getPassword()));
        user.setFirstName(signUpRequest.getFirstName());
        user.setLastName(signUpRequest.getLastName());
        user.setCreatedAt(LocalDateTime.now());
        user.setIsActive(true);
        user.setIsVerified(false);
        user.setFailedAttempts(0);
        user.setAccountLocked(false);
        
        userRepository.save(user);
        
        return ResponseEntity.status(HttpStatus.CREATED)
            .body(Map.of("message", "User registered successfully", "code", "USER_CREATED"));
    }
    
    @GetMapping("/validate")
    public ResponseEntity<?> validateToken(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        try {
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.ok(Map.of("valid", false, "error", "Missing or invalid Authorization header"));
            }
            
            String jwt = authHeader.substring(7);
            if (tokenProvider.validateToken(jwt)) {
                String username = tokenProvider.getUsernameFromToken(jwt);
                return ResponseEntity.ok(Map.of(
                    "valid", true,
                    "username", username
                ));
            }
            return ResponseEntity.ok(Map.of("valid", false, "error", "Token validation failed"));
        } catch (Exception e) {
            return ResponseEntity.ok(Map.of("valid", false, "error", "Invalid token format"));
        }
    }
}