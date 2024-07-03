package com.example.spring_jwt.service;

import com.example.spring_jwt.model.AuthenticationResponse;
import com.example.spring_jwt.model.Token;
import com.example.spring_jwt.model.User;
import com.example.spring_jwt.repository.ITokenRepository;
import com.example.spring_jwt.repository.IUserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AuthenticationService {

    @Autowired
    private IUserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private ITokenRepository tokenRepository;

    public AuthenticationResponse register(User request) {
        User user = new User();
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(request.getRole());

        user = userRepository.save(user);

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        //Guardamos el metodo
        saveUserToken(accessToken, refreshToken, user);

        return new AuthenticationResponse(accessToken, refreshToken);
    }

    private void saveUserToken(String accessToken, String refreshToken, User user) {
        Token token = new Token();
        token.setAccessToken(accessToken);
        token.setRefreshToken(refreshToken);
        token.setLoggedOut(false);
        token.setUser(user);
        tokenRepository.save(token);
    }

    public AuthenticationResponse authenticate(User userReq) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(userReq.getUsername(), userReq.getPassword())
        );
        User user = userRepository.findByUsername(userReq.getUsername()).orElseThrow();

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        revokeAllTokensByUser(user);

        //Guardamos el token
        saveUserToken(accessToken, refreshToken, user);

        return new AuthenticationResponse(accessToken, refreshToken);
    }

    private void revokeAllTokensByUser(User user) {
        //Simplemente invalidamos todos los tokens del usuario antes de guardar uno nuevo
        List<Token> validTokenListByUser = tokenRepository.findAllTokenByUser(user.getId());

        if (!validTokenListByUser.isEmpty()) {
            validTokenListByUser.forEach(
                    t -> {
                        t.setLoggedOut(true);
                    }
            );
        }

        tokenRepository.saveAll(validTokenListByUser);
    }

    public ResponseEntity refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ){
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")){
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }

        String token = authHeader.substring(7);

        String username = jwtService.extractUsername(token);
        //Comprobar si existe
        User user = userRepository.findByUsername(username)
                .orElseThrow( () -> new UsernameNotFoundException("No user found"));
        //Validar
        if (jwtService.isValidRefreshToken(token, user)) {
            String accessToken = jwtService.generateAccessToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);

            revokeAllTokensByUser(user);

            saveUserToken(accessToken, refreshToken, user);

            return new ResponseEntity(new AuthenticationResponse(accessToken, refreshToken), HttpStatus.OK);
        }
        return new ResponseEntity(HttpStatus.UNAUTHORIZED);
    }

}
