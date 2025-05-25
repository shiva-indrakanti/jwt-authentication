package com.jwt.authentication.entity;

import jakarta.persistence.*;

@Entity
@Table(name = "user_auth_table")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "username")
    private String username;

    @Column(name = "email_id")
    private String email;

    @Column(name = "password")
    private String password;

    @Column(name = "assigned_role")
    private String assignedRole;

    public User() {
    }

    public User(String username,String email, String password, String role) {
        this.username = username;
        this.email = email;
        this.password = password;
        this.assignedRole = role;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getAssignedRole() {
        return assignedRole;
    }

    public void setAssignedRole(String assignedRole) {
        this.assignedRole = assignedRole;
    }
}
