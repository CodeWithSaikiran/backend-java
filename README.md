# Authentication Backend Service

Spring Boot REST API for user authentication with JWT and refresh tokens.

## Features
- User registration and login with JWT
- Automatic token refresh (5 minutes before expiration)
- Brute force protection (account lockout after 5 failed attempts for 15 minutes)
- Token validation endpoints
- Detailed error responses with error codes
- BCrypt password encryption
- MySQL database integration
- Configurable CORS
- Stateless session management

## API Endpoints

### Authentication Endpoints
- `POST /api/auth/signup` - Register new user
- `POST /api/auth/login` - Login and get access + refresh tokens
- `POST /api/auth/refresh` - Refresh access token using refresh token
- `GET /api/auth/validate` - Validate JWT token and get user info

### Response Formats

**Login Success (200 OK):**
```json
{
  "token": "eyJhbGciOiJIUzUxMiJ9...",
  "refreshToken": "eyJhbGciOiJIUzUxMiJ9...",
  "username": "testuser",
  "email": "test@example.com",
  "message": "Login successful"
}
```

**Login Error (401 Unauthorized):**
```json
{
  "error": "Invalid username or password",
  "code": "INVALID_CREDENTIALS",
  "attemptsRemaining": 4
}
```

**Account Locked (401 Unauthorized):**
```json
{
  "error": "Account locked due to too many failed login attempts",
  "code": "ACCOUNT_LOCKED",
  "remainingMinutes": 14
}
```

## Environment Variables (Required)

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET` | See below | Secret key for JWT signing (min 32 chars). **REQUIRED in production** |
| `SPRING_DATASOURCE_URL` | `jdbc:mysql://mysql-db:3306/user_auth?useSSL=false&allowPublicKeyRetrieval=true` | MySQL connection URL |
| `SPRING_DATASOURCE_USERNAME` | `root` | Database username |
| `SPRING_DATASOURCE_PASSWORD` | `root123` | Database password |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:4200` | Comma-separated list of allowed origins |

## Configuration Properties

Edit `src/main/resources/application.yml`:

```yaml
server.port=8080
spring.datasource.url=${SPRING_DATASOURCE_URL:...}
spring.datasource.username=${SPRING_DATASOURCE_USERNAME:root}
spring.datasource.password=${SPRING_DATASOURCE_PASSWORD:root123}
jwt.secret=${JWT_SECRET:changeme}
jwt.expiration=86400000  # 24 hours in milliseconds
jwt.refresh-expiration=604800000  # 7 days in milliseconds
app.cors.allowed-origins=${CORS_ALLOWED_ORIGINS:http://localhost:4200}
app.auth.brute-force-max-attempts=5  # Failed login attempts before lockout
app.auth.brute-force-lock-duration-minutes=15  # Account lock duration
```

## Build & Run

### Prerequisites
- Java 17+
- Maven 3.6+
- MySQL 8.0+

### Local Development

```bash
# Build JAR
mvn clean package

# Run locally (ensure MySQL is running)
java -jar target/auth-backend-*.jar

# Run with environment variables
export JWT_SECRET="your-secret-key-at-least-32-characters-long"
export CORS_ALLOWED_ORIGINS="http://localhost:4200"
java -jar target/auth-backend-*.jar
```

### Docker

```bash
# Build image
docker build -t auth-backend:latest .

# Run container
docker run -p 8080:8080 \
  -e JWT_SECRET="your-secret-key" \
  -e SPRING_DATASOURCE_URL="jdbc:mysql://mysql-db:3306/user_auth" \
  -e SPRING_DATASOURCE_USERNAME="root" \
  -e SPRING_DATASOURCE_PASSWORD="root123" \
  auth-backend:latest
```

### Docker Compose

From project root:
```bash
docker-compose up -d
```

Environment variables can be set in `.env` file:
```
JWT_SECRET=your-secret-key-here
CORS_ALLOWED_ORIGINS=http://localhost:4200,http://app.example.com
```

## Security Considerations

1. **JWT Secret**: Must be at least 32 characters and unique per environment
   - Development: Can use default, but not recommended
   - Production: Must use strong random secret from secure vault

2. **Brute Force Protection**: 
   - Account locks after 5 failed attempts (configurable)
   - Lock duration: 15 minutes (configurable)
   - Provides feedback on remaining attempts

3. **Token Expiration**:
   - Access token: 24 hours
   - Refresh token: 7 days
   - Tokens automatically validated on each request

4. **CORS Configuration**:
   - Restrict to specific domains in production
   - Never use wildcard `*` in production

## Database

### Schema

Users table includes:
- `id` - Auto-generated primary key
- `username`, `email` - Unique identifiers
- `password_hash` - BCrypt hashed password
- `is_active`, `is_verified` - Account status flags
- `failed_attempts`, `account_locked` - Brute force tracking
- `lock_time` - Account lock timestamp
- `last_login` - Last successful login timestamp
- `created_at`, `updated_at` - Timestamps

### Initialize Database

```bash
# MySQL
mysql -u root -p < database-sql/init.sql

# Or via Docker
docker exec -i mysql-container mysql -u root -proot123 < database-sql/init.sql
```

## Testing Login Flow

```bash
# 1. Signup
curl -X POST http://localhost:8080/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "username":"testuser",
    "email":"test@example.com",
    "password":"Password123!",
    "firstName":"Test",
    "lastName":"User"
  }'

# 2. Login
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"Password123!"}'

# 3. Use access token
curl http://localhost:8080/api/protected \
  -H "Authorization: Bearer <ACCESS_TOKEN>"

# 4. Refresh token
curl -X POST http://localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<REFRESH_TOKEN>"}'

# 5. Validate token
curl http://localhost:8080/api/auth/validate \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```

## Troubleshooting

### "Invalid JWT secret" Error
- Ensure `JWT_SECRET` environment variable is set and matches across app restarts
- Must be at least 32 characters

### "CORS error" in Browser
- Check `CORS_ALLOWED_ORIGINS` includes your frontend domain
- Ensure frontend sends proper `Origin` header

### "Account locked" After Login Failures
- Account automatically unlocks after 15 minutes
- Or manually update database: `UPDATE users SET account_locked = false WHERE username = 'username'`

### MySQL Connection Failed
- Verify MySQL is running: `docker ps | grep mysql`
- Check connection URL and credentials match
- Test connection: `mysql -h localhost -u root -p`

## Error Codes

| Code | Meaning | Action |
|------|---------|--------|
| `INVALID_CREDENTIALS` | Wrong username/password | Retry with correct credentials |
| `ACCOUNT_LOCKED` | Too many failed attempts | Wait for unlock duration or contact support |
| `ACCOUNT_DISABLED` | User account is disabled | Contact support |
| `USER_INVALID` | User not found | Ensure username exists |
| `INVALID_REFRESH_TOKEN` | Refresh token invalid/expired | User must login again |
| `MISSING_REFRESH_TOKEN` | No refresh token provided | Include refreshToken in request body |

## Next Steps

- [ ] Implement password reset functionality
- [ ] Add email verification
- [ ] Add role-based access control (RBAC)
- [ ] Implement OAuth2/OIDC support
- [ ] Add 2FA (two-factor authentication)
- [ ] Implement audit logging
