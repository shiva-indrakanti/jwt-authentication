package com.jwt.authentication.service;
import com.jwt.authentication.entity.User;
import com.jwt.authentication.repo.IAuthRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private IAuthRepo repo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //implement custom exception(future)
        User user = repo.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        return new org.springframework.security.core.userdetails.User(user.getUsername(),
                                         user.getPassword(),List.of(new SimpleGrantedAuthority(user.getAssignedRole())));
    }
}
