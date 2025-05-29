package com.jwt.authentication.controller;

import com.jwt.authentication.dto.request.LoginRequest;
import com.jwt.authentication.dto.request.RegisterRequest;
import com.jwt.authentication.service.AuthenticationService;
import com.jwt.authentication.jwt.utils.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
public class AuthenticationController {

    @Autowired
    private AuthenticationService service;

    @Autowired
    private JwtUtils utils;

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterRequest request){
        String response = service.registerUser(request);
        return ResponseEntity.status(HttpStatus.CREATED).body("Registration Successful");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        return service.handleLogin(request);
    }

    @GetMapping("/private/profile")
    public ResponseEntity<String> getProfile(@RequestHeader("Authorization") String authHeader){
        return ResponseEntity.ok("Valid token,Here is your profile");
    }
}
