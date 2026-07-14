# JWT Security — Arquitectura Hexagonal

API REST de autenticación y autorización basada en JWT, construida con **Spring Boot 4.1** y **arquitectura hexagonal**. Incluye protección contra fuerza bruta, rate limiting por IP y observabilidad completa (métricas, trazas distribuidas y logs estructurados).

---

## 📋 Tabla de contenido

- [Stack tecnológico](#stack-tecnológico)
- [Arquitectura](#arquitectura)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Flujos implementados](#flujos-implementados)
- [Seguridad](#seguridad)
- [Observabilidad](#observabilidad)
- [API Reference](#api-reference)
- [Configuración](#configuración)
- [Ejecución local](#ejecución-local)
- [Tests](#tests)
- [Infraestructura de observabilidad](#infraestructura-de-observabilidad)

---

## Stack tecnológico

| Componente             | Tecnología                           |
|------------------------|--------------------------------------|
| Lenguaje               | Java 21                              |
| Framework              | Spring Boot 4.1.0                    |
| Seguridad              | Spring Security 7 + JWT (jjwt 0.13) |
| Persistencia           | Spring Data JPA + H2 (en memoria)   |
| Validación             | Jakarta Validation                   |
| Métricas               | Micrometer + Prometheus              |
| Trazas distribuidas    | OpenTelemetry + Jaeger               |
| Logs estructurados     | Logstash Logback Encoder + ELK       |
| Build                  | Maven 3                              |
| Boilerplate            | Lombok 1.18.46                       |

---

## Arquitectura

El proyecto sigue **arquitectura hexagonal** (Ports & Adapters). El dominio no conoce detalles de infraestructura; toda la comunicación ocurre a través de puertos.

```
┌─────────────────────────────────────────────────────────────┐
│                        DOMAIN                               │
│  Models: User, Token, Email, Password, Role, Permission     │
│  Ports (input):  LoginUserPort, RegisterUserPort,           │
│                  RefreshTokenPort, LogoutUserPort            │
│  Ports (output): UserRepositoryPort, TokenRepositoryPort,   │
│                  TokenGeneratorPort, PasswordEncoderPort,   │
│                  LoginAttemptPort, RateLimitPort             │
│  Exceptions: InvalidCredentialsException, AccountLocked-    │
│              Exception, RateLimitExceededException, …       │
└───────────────────────┬─────────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────────┐
│                     APPLICATION                             │
│  Use Cases: LoginUserUseCase, RegisterUserUseCase,          │
│             RefreshTokenUseCase, LogoutUserUseCase          │
│  DTOs: LoginCommand, RegisterCommand, RefreshTokenCommand,  │
│        LogoutCommand, TokenResult                           │
└───────────────────────┬─────────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────────┐
│                   INFRASTRUCTURE                            │
│  Input adapters:                                            │
│    REST:    AuthController, ProtectedController,            │
│             AccountsController, GlobalExceptionHandler      │
│    Filters: JwtAuthenticationFilter, TraceIdFilter          │
│    Interceptors: RateLimitInterceptor                       │
│  Output adapters:                                           │
│    Persistence: UserRepositoryAdapter, TokenRepositoryAdapter│
│    Security:    JwtTokenAdapter, BcryptPasswordAdapter,     │
│                 LoginAttemptAdapter, RateLimitAdapter        │
│  Config: SecurityConfig, BeanConfig, RateLimitConfig,       │
│          WebMvcConfig, TracingConfig                        │
│  Metrics: MetricsService                                    │
└─────────────────────────────────────────────────────────────┘
```

---

## Estructura del proyecto

```
jwt-security-hexagonal/
├── src/main/java/com/example/security/
│   ├── App.java
│   ├── domain/
│   │   ├── model/          # User, Token, Email, Password, Role, Permission
│   │   ├── port/
│   │   │   ├── input/      # LoginUserPort, RegisterUserPort, RefreshTokenPort, LogoutUserPort
│   │   │   └── output/     # UserRepositoryPort, TokenRepositoryPort, TokenGeneratorPort,
│   │   │                   # PasswordEncoderPort, LoginAttemptPort, RateLimitPort
│   │   └── exception/      # InvalidCredentialsException, InvalidTokenException,
│   │                       # AccountLockedException, RateLimitExceededException, …
│   ├── application/
│   │   ├── usecase/        # LoginUserUseCase, RegisterUserUseCase,
│   │   │                   # RefreshTokenUseCase, LogoutUserUseCase
│   │   └── dto/            # LoginCommand, RegisterCommand, RefreshTokenCommand,
│   │                       # LogoutCommand, TokenResult
│   └── infrastructure/
│       ├── adapter/
│       │   ├── input/
│       │   │   ├── annotation/   # RequireScope
│       │   │   ├── filter/       # JwtAuthenticationFilter, JwtAuthenticationEntryPoint,
│       │   │   │                 # TraceIdFilter
│       │   │   └── rest/         # AuthController, ProtectedController, AccountsController,
│       │   │       ├── dto/      # LoginRequestDto, RegisterRequestDto, TokenResponseDto, LogoutResponseDto
│       │   │       └── mapper/   # AuthMapper
│       │   └── output/
│       │       ├── persistence/  # UserRepositoryAdapter, TokenRepositoryAdapter,
│       │       │   ├── entity/   # UserJpaEntity, TokenJpaEntity
│       │       │   └── mapper/   # UserPersistenceMapper
│       │       └── security/     # JwtTokenAdapter, BcryptPasswordAdapter,
│       │                         # LoginAttemptAdapter, RateLimitAdapter
│       ├── config/               # SecurityConfig, BeanConfig, RateLimitConfig,
│       │                         # RateLimitProperties, WebMvcConfig, TracingConfig,
│       │                         # TracingCustomizer
│       └── metrics/              # MetricsService
├── src/main/resources/
│   ├── application.yml
│   └── logback-spring.xml
├── src/test/
│   ├── java/                     # Tests unitarios e integración
│   └── resources/
│       ├── application-test.yml
│       └── testdata/             # CSVs para tests parametrizados
├── docker-compose.yml            # ELK + Prometheus + Grafana + Jaeger + Alertmanager
├── prometheus.yml
├── prometheus/alert_rules.yml
├── alertmanager/alertmanager.yml
├── logstash/
│   ├── config/logstash.yml
│   └── pipeline/logstash.conf
└── pom.xml
```

---

## Flujos implementados

### 1. Register
```
POST /api/v1/auth/register
Content-Type: application/json

{
  "name": "Juan Pérez",
  "email": "juan@example.com",
  "password": "password123",
  "role": "CUSTOMER"
}
```
**Respuesta 201:**
```json
{
  "access_token": "<jwt>",
  "refresh_token": "<jwt>",
  "token_type": "Bearer",
  "expires_in": 86400
}
```

### 2. Login
```
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "juan@example.com",
  "password": "password123"
}
```
**Respuesta 200** igual que register. Tras **5 intentos fallidos** la cuenta se bloquea 15 minutos (429).

### 3. Refresh Token
```
POST /api/v1/auth/refresh
Authorization: Bearer <refresh_token>
```
**Respuesta 200** con nuevos access/refresh tokens. Los tokens anteriores quedan revocados.

### 4. Logout
```
POST /api/v1/auth/logout
Authorization: Bearer <access_token>
```
**Respuesta 200:**
```json
{
  "message": "Logout successful",
  "timestamp": "2026-07-14T21:00:00Z"
}
```
El token queda marcado como revocado y expirado en BD.

### 5. Endpoint protegido (ejemplo)
```
GET /api/v1/protected/me
Authorization: Bearer <access_token>
```
Requiere token válido en BD y no revocado. El filtro JWT valida firma, expiración y estado en base de datos.

---

## Seguridad

### Autenticación JWT
- Tokens firmados con HMAC-SHA (clave configurable).
- Access token: 24h · Refresh token: 7 días.
- Validación en BD para detectar tokens revocados/expirados.
- Roles y scopes embebidos en los claims (`roles`, `scopes`).

### Protección contra fuerza bruta
- **MAX_ATTEMPTS = 5** intentos fallidos por usuario.
- **LOCKOUT_DURATION = 15 minutos**.
- Almacenamiento en memoria (`ConcurrentHashMap`).
- Respuesta `429 Too Many Requests` durante el bloqueo.
- Reinicio automático del contador al login exitoso.

### Rate Limiting por IP
- `/api/v1/auth/login`: **20 requests/minuto** por IP.
- `/api/v1/auth/register`: **5 requests/hora** por IP.
- Headers de respuesta: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`.
- Extracción de IP real via `X-Forwarded-For` / `X-Real-IP`.
- Habilitado/deshabilitado por property (`rate-limit.enabled`).

### Manejo de errores
| Excepción                    | HTTP | Descripción                                   |
|------------------------------|------|-----------------------------------------------|
| `InvalidCredentialsException`| 401  | Email o contraseña incorrectos                |
| `InvalidTokenException`      | 401  | Token inválido, expirado o revocado           |
| `UserAlreadyExistsException` | 409  | Email ya registrado                           |
| `AccountLockedException`     | 429  | Cuenta bloqueada por fuerza bruta             |
| `RateLimitExceededException` | 429  | Rate limit por IP excedido                    |
| `InvalidRoleException`       | 400  | Rol inválido en registro                      |
| Validación de campos         | 400  | Campos requeridos ausentes o mal formateados  |

---

## Observabilidad

### Métricas (Micrometer + Prometheus)
Counters y timers registrados por `MetricsService`:

| Métrica                          | Tipo    | Descripción                            |
|----------------------------------|---------|----------------------------------------|
| `auth.login.success`             | Counter | Logins exitosos                        |
| `auth.login.failure`             | Counter | Logins fallidos                        |
| `auth.login.duration`            | Timer   | Latencia de operación login            |
| `auth.registration.success`      | Counter | Registros exitosos                     |
| `auth.registration.failure`      | Counter | Registros fallidos                     |
| `auth.registration.duration`     | Timer   | Latencia de operación registro         |
| `jwt.token.generated`            | Counter | Tokens JWT generados                   |
| `jwt.token.validated`            | Counter | Tokens JWT validados correctamente     |
| `jwt.token.expired`              | Counter | Tokens JWT expirados                   |
| `jwt.token.invalid`              | Counter | Tokens JWT inválidos                   |
| `jwt.token.revoked`              | Counter | Tokens JWT revocados                   |
| `jwt.refresh_token.generated`    | Counter | Refresh tokens generados               |
| `jwt.refresh_token.used`         | Counter | Refresh tokens utilizados              |
| `jwt.validation.duration`        | Timer   | Latencia de validación JWT             |
| `security.access.unauthorized`   | Counter | Accesos 401                            |
| `security.access.forbidden`      | Counter | Accesos 403                            |
| `security.credentials.invalid`   | Counter | Credenciales inválidas                 |
| `security.account.lockout`       | Counter | Cuentas bloqueadas                     |

Endpoint Prometheus: `GET /actuator/prometheus`

### Trazas distribuidas (OpenTelemetry + Jaeger)
- Bridge Micrometer → OpenTelemetry con exportador OTLP HTTP.
- `TraceIdFilter` enriquece MDC y cabeceras de respuesta (`X-Trace-Id`, `X-Span-Id`).
- `TracingCustomizer` permite agregar tags y eventos al span activo.
- Jaeger UI disponible en `http://localhost:16686`.

### Logs estructurados (ELK)
- `logback-spring.xml` con appender `LogstashTcpSocketAppender` (perfil no-test).
- Campos enriquecidos: `traceId`, `spanId`, `application`.
- Índice en Elasticsearch: `spring-boot-logs-YYYY.MM.dd`.
- Kibana disponible en `http://localhost:5601`.

### Alertas (Prometheus Alertmanager)
Reglas definidas en `prometheus/alert_rules.yml`:
- `ServiceDown` — servicio caído > 1 min.
- `HighCPUUsage` — CPU > 80% por 5 min.
- `HighMemoryUsage` — heap JVM > 85% por 5 min.
- `HighLoginFailureRate` — > 5 fallos/min (posible ataque).
- `HighInvalidTokenRate` — > 10 tokens inválidos/min.
- `UnauthorizedAccessAttempts` — > 10 intentos 401/min.
- `HighHTTPErrorRate` — > 5% requests con 5xx.
- `HighRequestLatency` — p95 > 1 segundo.

### Actuator endpoints disponibles
```
GET /actuator/health      → Estado de la aplicación
GET /actuator/metrics     → Listado de métricas
GET /actuator/prometheus  → Métricas en formato Prometheus
GET /actuator/info        → Información de la aplicación
```

---

## API Reference

| Método | Endpoint                   | Auth requerida | Descripción                    |
|--------|----------------------------|----------------|--------------------------------|
| POST   | `/api/v1/auth/register`    | No             | Registrar nuevo usuario        |
| POST   | `/api/v1/auth/login`       | No             | Iniciar sesión                 |
| POST   | `/api/v1/auth/refresh`     | No (Bearer)    | Renovar access token           |
| POST   | `/api/v1/auth/logout`      | Bearer         | Cerrar sesión                  |
| GET    | `/api/v1/protected/me`     | Bearer         | Endpoint protegido de ejemplo  |
| GET    | `/api/v1/accounts/**`      | Bearer + scope | Endpoint con control de scopes |
| GET    | `/actuator/**`             | No             | Endpoints de observabilidad    |
| GET    | `/h2-console`              | No             | Consola H2 (desarrollo)        |

---

## Configuración

### `application.yml` — propiedades clave

```yaml
server:
  port: 9100

application:
  security:
    jwt:
      secret-key: <base64>         # Clave HMAC para firmar JWT
      expiration: 86400000         # Access token: 24h (ms)
      refresh-token:
        expiration: 604800000      # Refresh token: 7 días (ms)

rate-limit:
  enabled: true
  login:
    max-requests: 20               # Máximo de logins por minuto por IP
    window-minutes: 1
  register:
    max-requests: 5                # Máximo de registros por hora por IP
    window-minutes: 60

tracing:
  enabled: true

otel:
  service:
    name: jwt-spring-security
  exporter:
    otlp:
      endpoint: http://localhost:4318   # Endpoint Jaeger OTLP

management:
  tracing:
    sampling:
      probability: 1.0            # 100% de requests trazadas (ajustar en producción)
```

### `application-test.yml` — overrides para tests

```yaml
spring:
  datasource:
    url: jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1

rate-limit:
  enabled: false                  # Deshabilitado en tests por defecto

tracing:
  enabled: false                  # Sin tracing en tests
```

### Variables de entorno (producción)

| Variable                                | Descripción                          |
|-----------------------------------------|--------------------------------------|
| `APPLICATION_SECURITY_JWT_SECRET_KEY`   | Clave secreta JWT (mínimo 256 bits)  |
| `APPLICATION_SECURITY_JWT_EXPIRATION`   | Expiración access token (ms)         |
| `OTEL_EXPORTER_OTLP_ENDPOINT`          | Endpoint del collector OTLP          |
| `RATE_LIMIT_ENABLED`                    | `true`/`false`                       |

---

## Ejecución local

### Requisitos
- Java 21+
- Maven 3.8+
- Docker + Docker Compose (para stack de observabilidad)

### Arrancar solo la aplicación

```bash
mvn spring-boot:run
```

La API queda disponible en `http://localhost:9100`.

### Arrancar con stack de observabilidad completo

```bash
# 1. Levantar infraestructura
docker-compose up -d

# 2. Arrancar la aplicación
mvn spring-boot:run
```

Servicios disponibles:

| Servicio       | URL                       |
|----------------|---------------------------|
| API            | http://localhost:9100     |
| H2 Console     | http://localhost:9100/h2-console |
| Actuator       | http://localhost:9100/actuator |
| Prometheus     | http://localhost:9090     |
| Grafana        | http://localhost:3000 (admin/admin) |
| Jaeger UI      | http://localhost:16686    |
| Kibana         | http://localhost:5601     |
| Alertmanager   | http://localhost:9093     |

---

## Tests

### Ejecutar todos los tests
```bash
mvn test
```

### Ejecutar tests específicos
```bash
# Tests de autenticación
mvn test -Dtest=LoginUserUseCaseTest,LoginUserIntegrationTest

# Tests de brute force
mvn test -Dtest=LoginAttemptAdapterTest,BruteForceProtectionIntegrationTest

# Tests de rate limiting
mvn test -Dtest=RateLimitAdapterTest,RateLimitIntegrationTest

# Tests del filtro JWT
mvn test -Dtest=JwtAuthenticationFilterTest
```

### Cobertura de tests

| Categoría               | Tests incluidos                                                  |
|-------------------------|------------------------------------------------------------------|
| **Domain Models**       | `EmailTest`, `PasswordTest`, `RoleTest`                         |
| **Use Cases (Unit)**    | `LoginUserUseCaseTest`, `RegisterUserUseCaseTest`, `RefreshTokenUseCaseTest`, `LogoutUserUseCaseTest` |
| **Adapters (Unit)**     | `LoginAttemptAdapterTest`, `RateLimitAdapterTest`               |
| **Filter (Unit)**       | `JwtAuthenticationFilterTest`                                   |
| **Integration**         | `LoginUserIntegrationTest`, `RefreshTokenIntegrationTest`, `ProtectedEndpointIntegrationTest`, `LogoutIntegrationTest`, `BruteForceProtectionIntegrationTest`, `RateLimitIntegrationTest`, `AccountsControllerIntegrationTest` |

Los tests de use case siguen patrón **TDD + AAA** (Arrange / Act / Assert) con Mockito. Los tests de integración arrancan el contexto completo (`@SpringBootTest`) con base de datos H2 en memoria.

Los tests parametrizados usan CSV en `src/test/resources/testdata/`:
- `valid-logins.csv`, `invalid-logins.csv`
- `valid-users.csv`, `invalid-users.csv`
- `brute-force-scenarios.csv`

---

## Infraestructura de observabilidad

### `docker-compose.yml`

| Servicio       | Imagen                         | Puerto(s)        | Rol                            |
|----------------|--------------------------------|------------------|--------------------------------|
| Elasticsearch  | `elasticsearch:8.11.0`         | 9200, 9300       | Almacenamiento de logs         |
| Logstash       | `logstash:8.11.0`              | 5000, 9600       | Procesamiento de logs TCP/JSON |
| Kibana         | `kibana:8.11.0`                | 5601             | Visualización de logs          |
| Prometheus     | `prom/prometheus:latest`       | 9090             | Recolección de métricas        |
| Grafana        | `grafana/grafana:latest`       | 3000             | Dashboards de métricas         |
| Jaeger         | `jaegertracing/all-in-one`     | 16686, 4317, 4318| Trazas distribuidas            |
| Alertmanager   | `prom/alertmanager:latest`     | 9093             | Gestión de alertas             |

### Alertas configuradas

Definidas en `prometheus/alert_rules.yml`, agrupadas en tres categorías:
- **Infraestructura**: `ServiceDown`, `HighCPUUsage`, `HighMemoryUsage`
- **Seguridad**: `HighLoginFailureRate`, `HighInvalidTokenRate`, `UnauthorizedAccessAttempts`
- **Aplicación**: `HighHTTPErrorRate`, `HighRequestLatency`

Para producción, actualiza `alertmanager/alertmanager.yml` con tu webhook o configuración de email/Slack:
```yaml
receivers:
  - name: 'webhook-receiver'
    webhook_configs:
      - url: 'https://webhook.site/YOUR-WEBHOOK-ID'
```

---

## Principios y patrones aplicados

- **Arquitectura hexagonal** — separación estricta dominio / aplicación / infraestructura.
- **SOLID** — cada clase tiene una responsabilidad, las dependencias apuntan hacia adentro.
- **Domain-Driven Design (DDD)** — objetos de valor (`Email`, `Password`), entidades (`User`, `Token`) y puertos.
- **TDD** — tests escritos antes o en paralelo con la implementación.
- **Patrones**: Port & Adapter, Command, Repository, Factory Method.
- **Thread safety** — `ConcurrentHashMap` y operaciones atómicas en adapters en memoria.

---

## Licencia

Proyecto de uso educativo — Bootcamp Lab 7.
