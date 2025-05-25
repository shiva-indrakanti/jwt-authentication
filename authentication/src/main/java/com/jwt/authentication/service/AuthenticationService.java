package com.jwt.authentication.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.jwt.authentication.dto.request.LoginRequest;
import com.jwt.authentication.dto.request.RegisterRequest;
import com.jwt.authentication.dto.response.LoginResponse;
import com.jwt.authentication.dto.response.UserDto;
import com.jwt.authentication.entity.CustomUserDetails;
import com.jwt.authentication.entity.User;
import com.jwt.authentication.repo.IAuthRepo;
import com.jwt.authentication.jwt.utils.JwtUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@Service
public class AuthenticationService {

    @Autowired
    private IAuthRepo repo;

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationService.class);
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtils utils;

    @Autowired
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public String registerUser(RegisterRequest request) {
        if(request == null){
            throw new RuntimeException("Request is null");
        }
        if(!request.getPassword().equals(request.getConfirmPassword())){
            throw new RuntimeException("Passwords are not matched");
        }
        User user = new User(request.getUsername(),request.getEmail(),request.getPassword(),request.getRole());
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        repo.save(user);
        return "Registration Successful";
    }

    public ResponseEntity<?> handleLogin(LoginRequest request) {
        try{
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
            CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
            LOGGER.info("User Details = "+userDetails);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            String token = utils.generateToken(userDetails.getUsername(),600);
            long now = System.currentTimeMillis()/1000;
            UserDto userDto = new UserDto(userDetails.getUsername(),userDetails.getEmail(),userDetails.getRole());
            LoginResponse response = new LoginResponse(token,600,now,userDto);
            return ResponseEntity.ok(response);
        }catch(BadCredentialsException ex){
            LOGGER.error("Invalid Credentials",ex);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Credentials");
        } catch (JsonProcessingException | NoSuchAlgorithmException | InvalidKeyException e) {
            LOGGER.error("Exception occurred during Token generation",e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Token Generation failed");
        }catch(Exception ex){
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Unexpected error");
        }
    }
}
