package com.czavala.springjwt.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
public class JwtService {

    private static final String SECRET_KEY = "";

    // extrae el username desde el token
    public String extractUsername(String token) {
        // getSubject indica que obtiene el username
        return getClaim(token, claims -> claims.getSubject());
    }

    // extrae un claims en especifico (el que se le indique) desde el token
    public <T> T getClaim(String token, Function<Claims, T> claimResolver) {
        final Claims claims = getAllClaims(token);
        return claimResolver.apply(claims);
    }

    // obtiene todos los claims desde el token
    public Claims getAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // genera token sin extra claims, solo con los detalles del usuario
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    // metodo para generar le token jwt con extra claims y los detalles del usuario
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts.builder()
                .setClaims(extraClaims)
                // agrega username del usuario al token
                .setSubject(userDetails.getUsername())
                // agrega fecha de emision del token es la fecha actual del sistema (en milisegundos)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                // agrega fecha de expiracion, token es valido por 12 horas a partir de la fecha de emision del token
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 12))
                // agrega la clave de firma del token y ocupa el algoritmo HS256
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                // construye token con la informacion previa
                .compact();
    }

    // verifica que token sea valido; que aun no haya expirado y que user del token corresponda al username de los detalles del user
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    // chequea que el token haya expirado (fecha de expíracion previa a la fecha actual del sistema)
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // obtiene la fecha de expiracion del token jwt
    private Date extractExpiration(String token) {
        return getClaim(token, claims -> claims.getExpiration());
    }

    // obtiene clave de firma
    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        // retorna instancia de clave secreta usando HMAC
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
