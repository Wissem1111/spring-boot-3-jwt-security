package com.securityJwt;
import com.securityJwt.auth.AuthenticationService;

import com.securityJwt.auth.RegisterRequest;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import static com.securityJwt.user.Role.ADMIN;
import static com.securityJwt.user.Role.MANAGER;

@SpringBootApplication
public class SecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityApplication.class, args);
	}

	@Bean
	public CommandLineRunner commandLineRunner(
			AuthenticationService service
	) {
		return args -> {
			var admin = RegisterRequest.builder()
					.fullName("Admin")
					.email("admin@example.com")
					.password("password")
					.role(ADMIN)
					.build();
			System.out.println("Admin token: " + service.register(admin).getAccessToken());

			var manager = RegisterRequest.builder()
					.fullName("Manager")
					.email("manager@example.com")
					.password("password")
					.role(MANAGER)
					.build();

			System.out.println("Manager token: " + service.register(manager).getAccessToken());
		};
	}


}
