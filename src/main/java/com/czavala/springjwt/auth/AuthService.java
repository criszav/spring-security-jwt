package com.czavala.springjwt.auth;

import com.czavala.springjwt.jwt.JwtService;
import com.czavala.springjwt.user.Role;
import com.czavala.springjwt.user.User;
import com.czavala.springjwt.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;


    public AuthResponse register(RegisterRequest registerRequest) {
        // crea el nuevo usuario y asigna los valores entregados por el usuario que se esta registrando
        var user = User.builder()
                .username(registerRequest.getUsername())
                // codifica la clave antes de guardarle en DB
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .firstname(registerRequest.getFirstname())
                .lastname(registerRequest.getLastname())
                // por defecto asigna el rol USER
                .role(Role.USER)
                .build();

        // guarda nuevo usuario en DB
        userRepository.save(user);

        // genera un token con los nuevos datos del usuario registrado
        var jwt = jwtService.generateToken(user);

        // retorna el AuthResponse con el nuevo token generado previamente
        return AuthResponse.builder()
                .token(jwt)
                .build();
    }

    public AuthResponse login(LoginRequest loginRequest) {

        // gestiona la autenticacion del usuario que quiere ingresar
        authenticationManager.authenticate(
                // se pasa por parametro credenciales de usuario que realiza login
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );

        // obtiene al usuario en DB para generar token
        var user = userRepository
                .findUserByUsername(loginRequest.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // genera token con los datos del usuario que esta realizando login
        var jwt = jwtService.generateToken(user);

        // retorna la respuesta que contiene el token generado previamente
        return AuthResponse.builder()
                .token(jwt)
                .build();
    }
}
