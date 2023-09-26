package com.czavala.springjwt.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // obtiene header "Authorization" desde el request, quien contiene el token
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        final String jwt;
        final String username;

        // si header viene vacío o sin el token, retorna a la cadena de filtros
        if (authHeader == null || !authHeader.contains("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // extrae el token desde el header (Authentication -> "Bearer ")
        jwt = authHeader.substring(7);

        // extrae username desde el token jwt
        username = jwtService.extractUsername(jwt);

        // verifica si user no esta autenticado
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            // obtiene data del user desde DB
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            // valida que el token sea valido
            if (jwtService.isTokenValid(jwt, userDetails)) {

                // si token es valido, se crea un username password token, pasando los detalles del usuario y las authorities
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                // actualiza SecurityContextHolder con el authToken creado previamente
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        // pasa al siguiente filtro de la cadena de filtros
        filterChain.doFilter(request, response);
    }
}
