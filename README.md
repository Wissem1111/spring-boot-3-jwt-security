# Spring Boot 3 + Spring Security 6 - JWT Authentication and Authorization

This project demonstrates how to implement user authentication and authorization using **Spring Boot 3**, **Spring Security 6**, and **JWT (JSON Web Token)**. It includes features such as role-based access control, token revocation, and refresh tokens.

---

## Features

- User Registration and Login
- JWT Access and Refresh Tokens
- Role-Based Authorization (USER, ADMIN, MANAGER)
- Token Revocation on Logout
- Secure Admin and Management Endpoints
- Refresh Token Handling
- Stateless Session Management

---

## Project Structure

```
src/main/java/com/example/
│
├── auth/
│   ├── AuthenticationController
│   ├── AuthenticationRequest
│   ├── AuthenticationResponse
│   ├── AuthenticationService
│   └── RegisterRequest
│
├── config/
│   ├── ApplicationConfig
│   ├── JwtAuthenticationFilter
│   ├── JwtService
│   ├── LogoutService
│   └── SecurityConfiguration
│
├── demo/
│   ├── AdminController
│   ├── DemoController
│   └── ManagementController
│
├── token/
│   ├── Token
│   ├── TokenRepository
│   └── TokenType
│
└── user/
    ├── Permission
    ├── Role
    ├── User
    └── UserRepository
```

---

##  Role-Based Endpoint Access

### Public Access

- \`POST /api/v1/auth/register\`
- \`POST /api/v1/auth/authenticate\`
- \`POST /api/v1/auth/refresh-token\`

### Secured Access

| Endpoint                    | Role                  | Authority Required                                           |
|-----------------------------|------------------------|--------------------------------------------------------------|
| /api/v1/admin/**            | ADMIN                  | admin:read, admin:create, admin:update, admin:delete         |
| /api/v1/management/**       | ADMIN, MANAGER         | manager:read, manager:create, manager:update, manager:delete |
| /api/v1/demo-controller     | Any authenticated user |                              —                               |

---

## Token Details

- **Access Token**: Short-lived JWT used for authorizing API requests.
- **Refresh Token**: Long-lived token used to obtain a new access token.
- Tokens are **revoked on logout** to ensure security.

---

## How to Run

### Prerequisites

- Java 17+
- Maven
- PostgreSQL database

### Run Locally

1. **Clone the repository**

```bash
git clone [https://github.com/Wissem1111/spring-boot-3-jwt-security.git]
cd spring-boot-3-jwt-security
```

2. **Configure `application.yaml`**

Update your database connection and JWT secret key:

```yaml
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/your_db
    username: postgres
    password: root
  jpa:
    hibernate:
      ddl-auto: create-drop
application:
  security:
    jwt:
      secret-key: your-secure-random-256-bit-key
```

3. **Run the application**

```bash
./mvnw spring-boot:run
```

---

## Notes

- Your `.yaml` file contains sensitive data like database passwords and secret keys. **DO NOT** commit them to your public repo.
- Use environment variables or `application-prod.yaml` with `@Profile("prod")` for secure deployment.

---

## Concepts Covered

-  Spring Boot 3 + Spring Security 6 Configuration
-  JWT Access and Refresh Tokens
-  Stateless Security with Filters
-  Role and Authority Management with Enums
-  Logout Handling and Token Revocation

---

##  Author

Made by **Wissem Bagga**

- GitHub: [Wissem1111](https://github.com/Wissem1111/)
- LinkedIn: [Wissem Bagga](https://www.linkedin.com/in/wissem-bagga-369917231/)

---
