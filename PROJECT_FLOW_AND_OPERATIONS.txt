DISTRIBUTED TOTP ENGINE - PROJECT FLOW AND OPERATIONS GUIDE

Date: 2026-06-20
Project: Distributed TOTP Engine (Spring Boot)

==================================================
1) WHAT THIS PROJECT DOES
==================================================
This service provides MFA setup and verification using RFC-style TOTP.

Primary APIs:
- POST /api/v1/mfa/setup
- POST /api/v1/mfa/verify

High-level purpose:
- Generate a TOTP secret for a user during setup.
- Encrypt and store that secret in DB.
- Verify submitted 6-digit codes with skew tolerance.
- Block token replay by tracking used code/time-step combinations.
- Expose operational endpoints through Spring Actuator.


==================================================
2) IMPLEMENTATION SUMMARY (WHAT IS ALREADY BUILT)
==================================================
Implemented major areas:
- Layered architecture (API, application, domain, infrastructure).
- TOTP generation engine with configurable:
  - time step
  - skew window
  - HMAC algorithm (SHA1/SHA256/SHA512 via enum and strategy factory)
- Secret encryption at rest using AES/GCM.
- Replay protection cache (thread-safe in-memory implementation).
- JPA persistence with Flyway migrations.
- H2 dev profile and PostgreSQL prod profile.
- Security configuration with stateless policy and actuator role-based protection.
- Centralized exception handling with uniform auth-failure response strategy.
- Request correlation with X-Request-ID filter.
- Metrics and health endpoints via Actuator + Micrometer.
- JIT warm-up runner for startup performance stabilization.
- JUnit test suite and JaCoCo coverage integration.


==================================================
3) END-TO-END REQUEST FLOW
==================================================
3.1 Setup Flow (POST /api/v1/mfa/setup)
1. Controller validates request fields.
2. Application service checks if user already has enabled MFA.
   - If enabled, returns conflict behavior.
3. Service generates 20-byte random secret.
4. Secret is Base32 encoded for TOTP use.
5. Base32 secret is encrypted with AES/GCM and stored in DB.
6. Service returns otpauth URI to client.

3.2 Verify Flow (POST /api/v1/mfa/verify)
1. Controller validates userId and 6-digit code format.
2. Service loads user profile from repository.
3. Service verifies MFA is enabled for user.
4. Encrypted secret is decrypted.
5. Decrypted Base32 secret is decoded into raw bytes.
6. TOTP engine generates valid codes for current time +/- skew window.
7. Submitted code is compared in constant-time style logic.
8. If no match -> invalid code error path.
9. If matched -> replay cache markUsed(userId, code, timeStep).
   - If already used -> replay attack error path.
10. On success -> verification success response.
11. Raw secret bytes are wiped in finally block.


==================================================
4) SECURITY MODEL
==================================================
4.1 HTTP Security
- Stateless session policy is enabled.
- CSRF is disabled for API-style stateless service.
- API endpoints under /api/v1/mfa/** are currently permitted in app config
  (typical auth expected at gateway/upstream boundary).
- Actuator endpoints are protected with HTTP Basic and ACTUATOR role.
- /actuator/health/** is public for probe usage.

4.2 Input Validation
- userId is required, length-limited, and cannot contain colon (:).
  Reason: replay key uses userId:code:timeStep format.
- verify code must be exactly 6 digits.
- Bean validation errors are mapped to structured 400 responses.

4.3 Secret Protection
- Secret stored encrypted in DB, not plaintext.
- Algorithm: AES/GCM (authenticated encryption).
- Random IV generated per encryption.
- Tamper detection handled through GCM tag verification failures.
- Raw secret bytes are zeroed after verification use.

4.4 Authentication Failure Hardening
- Multiple auth-related exceptions are mapped to uniform 401 semantics.
- Helps reduce user enumeration and oracle-style leakage.


==================================================
5) SECRET MANAGEMENT AND JVM HANDLING
==================================================
5.1 Secret Source
Environment variable expected:
- TOTP_ENCRYPTION_KEY

Expected format:
- Base64-encoded key
- Decoded size must be exactly 32 bytes (AES-256 key)

5.2 Startup Validation
At startup, the application validates:
- env var exists
- value is valid Base64
- decoded key length is exactly 32 bytes

If invalid, startup fails fast.

5.3 JVM-Level Handling in This Project
- No plaintext secrets are persisted.
- Decrypted raw secret bytes are cleaned after use in finally block.
- JIT warm-up is implemented to stabilize early runtime performance.
- Virtual threads are enabled in app config for concurrent request handling.
- No custom JVM flags are committed in this repo by default; runtime uses JVM defaults unless provided externally.


==================================================
6) CONCURRENCY MODEL
==================================================
6.1 Request Concurrency
- Spring Boot app handles concurrent HTTP requests.
- Virtual threads are enabled via configuration.

6.2 Replay Cache Thread Safety
- In-memory replay cache uses ConcurrentHashMap.
- Replay insert is atomic via putIfAbsent.
- This prevents time-of-check/time-of-use races for token reuse checks.

6.3 Scheduled Eviction
- A scheduled daemon thread periodically evicts old replay entries.
- Eviction errors are logged and counted; task is designed not to die silently.

6.4 Important Deployment Note
- Current replay cache implementation is process-local.
- In multi-instance deployments, use a shared distributed cache (for example Redis)
  to enforce replay guarantees across all replicas.


==================================================
7) DATABASE ACCESS AND MANAGEMENT
==================================================
7.1 Profiles
Dev profile:
- H2 in-memory DB

Prod profile:
- PostgreSQL with HikariCP tuning

7.2 Migrations
Flyway migration files are used:
- V1 creates user_mfa_profile table and index
- V2 adds constraint (portable SQL)

7.3 Persistence Pattern
- Spring Data JPA repository handles user profile reads/writes.
- findByUserId is cacheable with query hints.
- Entity includes @Version for optimistic locking.

7.4 Caching Strategy
- Hibernate L2 cache is configured with Caffeine.
- Query cache for repository reads is enabled via hints.

7.5 Transaction Scope
- Setup flow uses transactional write behavior.
- Verify flow is read-only transaction for DB operations.
- Replay cache operation is outside DB transaction (in-memory side effect).


==================================================
8) OBSERVABILITY AND OPERATIONS
==================================================
8.1 Actuator Endpoints
Base path:
- /actuator

Exposed endpoints include:
- health
- metrics
- prometheus
- info

8.2 Readiness and Liveness
- Liveness/readiness states enabled.
- Custom DB readiness indicator checks connectivity using SELECT 1.

8.3 Metrics and Auditing
- Micrometer metrics used for counters and timers.
- Verification decorator adds structured success/failure logging and timing metrics.
- RequestId filter propagates/generates X-Request-ID and binds MDC for log correlation.


==================================================
9) COMMANDS TO BUILD, TEST, RUN
==================================================
9.1 Prerequisites
- Java 21 recommended by build config.
- Maven available (or use explicit local path).
- Required env var:
  - TOTP_ENCRYPTION_KEY

PowerShell example (set env var for session):
- $env:TOTP_ENCRYPTION_KEY="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

9.2 Maven Commands
From project root:
- mvn clean compile
- mvn test
- mvn spring-boot:run

If Maven is not on PATH, install/configure Maven on your system and rerun
the same commands from the project root.

9.3 Helper Batch Scripts in Repo
- run-tests.bat
- run-coverage.bat

Coverage report target:
- target/site/jacoco/index.html


==================================================
10) QUICK API CHECK EXAMPLES
==================================================
10.1 Setup
POST /api/v1/mfa/setup
Body:
{
  "userId": "user123",
  "label": "user123@EnterpriseIAM"
}

10.2 Verify
POST /api/v1/mfa/verify
Body:
{
  "userId": "user123",
  "code": "123456"
}

10.3 Actuator Health
GET /actuator/health

10.4 Actuator Metrics (requires basic auth)
GET /actuator/metrics


==================================================
11) KNOWN LIMITATIONS / PRACTICAL NOTES
==================================================
- In-memory replay cache does not provide cross-node replay protection.
- Replay cache state is reset on process restart.
- API auth is currently permissive in service-level security config for /api/v1/mfa/**;
  upstream gateway auth is expected for production architecture.
- Ensure strong, rotated production encryption key management.


==================================================
12) SUGGESTED NEXT HARDENING STEPS
==================================================
- Move replay cache to distributed backend (Redis) for multi-instance correctness.
- Enforce service-level auth for /api/v1/mfa/** if gateway trust boundary changes.
- Add key rotation strategy and key versioning for encrypted secrets.
- Add integration tests that validate actuator security and profile-specific Flyway behavior.
- Add runbook for incident handling (DB down, key misconfiguration, replay anomaly spikes).

End of document.
