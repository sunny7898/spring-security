package com.security.SpringSecEx.config;

import com.security.SpringSecEx.service.JWTService;
import com.security.SpringSecEx.service.MyUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtFilter extends OncePerRequestFilter {  // Since we want this filter to be executed only once per request

    @Autowired
    private JWTService jwtService;

    @Autowired
    ApplicationContext context;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        // Step 1: Get the auth token
        String authHeader = request.getHeader("Authorization");
        String token = null;
        String username = null;

        // Step 2: Extract the token from the auth header and username from the token
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
            username = jwtService.extractUserName(token);
        }

        // Step 3: Verify if the user is not already authenticated.
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            // Getting the user (and its details) from the DB
            UserDetails userDetails = context.getBean(MyUserDetailsService.class).loadUserByUsername(username);

            // we have to validate the user the token contains is a part of the db, for this we would have to use userdetails
            if (jwtService.validateToken(token, userDetails)) {

                // Generate the session token - Creates an authentication object with the user's identity and roles.
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities());

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Set the token into the context, so that the session begins for the user
                SecurityContextHolder.getContext().setAuthentication(authToken);

            }
        }
        // Passes the request/response along the filter chain.
        filterChain.doFilter(request, response);
    }
}
