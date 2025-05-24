package com.jwt.authentication.service;

import com.jwt.authentication.dto.request.LoginRequest;
import com.jwt.authentication.dto.request.RegisterRequest;
import com.jwt.authentication.entity.User;
import com.jwt.authentication.repo.IAuthRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {

    @Autowired
    private IAuthRepo repo;


    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public String registerUser(RegisterRequest request) {
        if(request == null){
            throw new RuntimeException("Request is null");
        }
        if(!request.getPassword().equals(request.getConfirmPassword())){
            throw new RuntimeException("Passwords are not matched");
        }
        User user = new User(request.getUsername(),request.getPassword(),request.getRole());
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        repo.save(user);
        return "Registration Successful";
    }

    public String verifyUser(LoginRequest request) {
        Authentication unAuthenticatedToken = new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword());
        try{
            Authentication authentication = authenticationManager.authenticate(unAuthenticatedToken);
            if(authentication.isAuthenticated()){
                return "User Authenticated";
            }
        }catch(RuntimeException ex){
            System.out.println("exception in verify user method");
            ex.printStackTrace();
        }
        return "Invalid Username or Password";
    }
}
