package bouali.restday.bouali.services;

import bouali.restday.bouali.auth.AuthenticationRequest;
import bouali.restday.bouali.auth.AuthenticationResponse;
import bouali.restday.bouali.config.RegisterRequest;
import bouali.restday.bouali.repository.UserRepository;
import bouali.restday.bouali.user.Role;
import bouali.restday.bouali.user.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository repository;

    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user=repository.findByEmail(request.getEmail())
                .orElseThrow();
        var jwtToken=jwtService.generateToken(user);
        return  AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
    public AuthenticationResponse register(RegisterRequest request) {
        var user =User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .password(passwordEncoder.encode(request.getPassword()))
                .email(request.getEmail())
                .role(Role.ADMIN)
                .build();
        repository.save(user);
        var jwtToken=jwtService.generateToken(user);
        return  AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}
