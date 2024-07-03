package com.example.spring_jwt.service;

import com.example.spring_jwt.model.User;
import com.example.spring_jwt.repository.ITokenRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoder;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.hibernate.query.sql.internal.ParameterRecognizerImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${application.security.jwt.secret-key}")
    private String secretKey;

    @Value("${application.security.jwt.access-token-expiration}")
    private long accessTokenExpire;

    @Value("${application.security.jwt.refresh-token-expiration}")
    private long refreshTokenExpire;

    @Autowired
    private ITokenRepository tokenRepository;

    //Extrae la expiracion
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    //Varifica si el token esta expirado
    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    //Verifica si el token es valido
    public boolean isValid(String token, UserDetails userDetails) {
        String username = extractUsername(token);

        boolean isValidToken = tokenRepository.findByAccessToken(token)
                .map(t -> !t.isLoggedOut()).orElse(false);

        //Si el username es igual, y si el token no esta espirado
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token) && isValidToken;
    }

    public boolean isValidRefreshToken(String token, UserDetails userDetails) {
        String username = extractUsername(token);

        boolean isValidRefreshToken = tokenRepository.findByRefreshToken(token)
                .map(t -> !t.isLoggedOut()).orElse(false);

        //Si el username es igual, y si el token no esta espirado
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token) && isValidRefreshToken;
    }

    //Extrae el username
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    //Extrae los claims
    public <T> T extractClaim(String token, Function<Claims, T> resolver) {
        Claims claims = extractAllClaims(token);
        return resolver.apply(claims);
    }

    //Extract the payload
    private Claims extractAllClaims(String token) {
        return Jwts
                .parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }


    private String generateToken(User user, long expirationTime) {
        return Jwts
                .builder()
                .subject(user.getUsername())
                .issuedAt(new Date())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expirationTime))  //1 dia
                .signWith(getSigningKey())
                .compact();
    }

    public String generateAccessToken(User user) {
        return generateToken(user, accessTokenExpire);
    }

    public String generateRefreshToken(User user) {
        return generateToken(user, refreshTokenExpire);
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }


}
