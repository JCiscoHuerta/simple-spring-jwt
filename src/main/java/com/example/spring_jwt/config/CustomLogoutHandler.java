package com.example.spring_jwt.config;

import com.example.spring_jwt.model.Token;
import com.example.spring_jwt.repository.ITokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

@Component
public class CustomLogoutHandler implements LogoutHandler {

    @Autowired
    private ITokenRepository tokenRepository;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String authHeader = request.getHeader("Authorization");

        if (authHeader==null || !authHeader.startsWith("Bearer ")) {
            return;
        }

        String token = authHeader.substring(7);

        //Obtenemos el token de la db
        Token storedToken = tokenRepository.findByAccessToken(token)
                .orElse(null);
        if (token!=null) {
            storedToken.setLoggedOut(true);
            tokenRepository.save(storedToken);
        }
    }
}
