package com.jwt.authentication.repo;

import com.jwt.authentication.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface IAuthRepo extends JpaRepository<User,Long> {
    Optional<User> findByUsername(String username);
}
