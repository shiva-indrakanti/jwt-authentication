package com.jwt.authentication.controller;

import com.jwt.authentication.dto.request.LoginRequest;
import com.jwt.authentication.dto.request.RegisterRequest;
import com.jwt.authentication.service.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthenticationController {

    @Autowired
    private AuthenticationService service;

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterRequest request){
        String response = null;
        response = service.registerUser(request);
        return ResponseEntity.status(HttpStatus.CREATED).body("Registration Successful");
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginRequest request){
        return ResponseEntity.status(HttpStatus.FOUND).body("Authenticated");
    }
}
