package com.dcl.accommodate.security.filters;

import com.dcl.accommodate.security.jwt.JwtService;
import com.dcl.accommodate.security.jwt.JwtType;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

@AllArgsConstructor
public class JwtFilters extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final JwtType jwtType;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String tokenHead = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (tokenHead != null && tokenHead.startsWith("Bearer")) {
            String token = tokenHead.substring(7);

            Jws<Claims> claimsJws = jwtService.parseToken(token);
            Claims claims = claimsJws.getBody();

            String type = claimsJws.getHeader().getType();
            if (!jwtType.name().equalsIgnoreCase(type)) {
                throw new JwtException("Invalid JWT type: expected " + jwtType + " but got " + type);
            }
            String username = claims.getSubject();
            String role = claims.get("role", String.class);

            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                var authentication = new UsernamePasswordAuthenticationToken(
                        username,
                        null,
                        Collections.singletonList(new SimpleGrantedAuthority(role))
                );

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }


        } else {
            System.out.println("no jwt token found in request header");
        }
        filterChain.doFilter(request, response);
    }
}
