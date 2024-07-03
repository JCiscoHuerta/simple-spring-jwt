package com.example.spring_jwt.model;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Table(name = "token")
@Data
public class Token {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Column(name = "access_token")
    private String accessToken;

    @Column(name = "is_logged_out")
    private boolean loggedOut;

    @Column(name = "refresh_token")
    private String refreshToken;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;
}
