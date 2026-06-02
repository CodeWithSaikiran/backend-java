# Authentication Backend Service

Spring Boot REST API for user authentication with JWT.

## Features
- User registration
- Login with JWT token
- Token validation
- Password encryption (BCrypt)
- MySQL database integration

## API Endpoints
- POST /api/auth/signup - Register new user
- POST /api/auth/login - Login and get JWT token
- GET /api/auth/validate - Validate JWT token

## Environment Variables
- JWT_SECRET: Secret key for JWT (required, min 32 chars)
- SPRING_DATASOURCE_URL: MySQL connection URL
- SPRING_DATASOURCE_USERNAME: Database username
- SPRING_DATASOURCE_PASSWORD: Database password

## Build & Run
\`\`\`bash
# Build JAR
mvn clean package

# Run locally
java -jar target/*.jar

# Or with Docker
docker build -t auth-backend .
docker run -p 8080:8080 auth-backend
\`\`\`

## Docker Compose Integration
\`\`\`yaml
backend:
  build: ./auth-backend-java
  ports:
    - "8080:8080"
  environment:
    - JWT_SECRET=${JWT_SECRET}
    - SPRING_DATASOURCE_URL=jdbc:mysql://mysql-db:3306/user_auth
  depends_on:
    - mysql-db
\`\`\`