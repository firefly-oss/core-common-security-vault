# Security Overview

## Introduction

The Firefly Security Vault is designed with security as the top priority. This document outlines the security features, encryption mechanisms, and best practices.

## Security Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                       │
│                  (Business Logic & API)                     │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                  Encryption Layer                           │
│              (AES-256-GCM Encryption)                       │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  1. Generate Data Encryption Key (DEK)              │  │
│  │  2. Encrypt credential with DEK                     │  │
│  │  3. Encrypt DEK with Master Key                     │  │
│  │  4. Store encrypted credential + encrypted DEK      │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                  Key Management Layer                       │
│                  (KMS Provider)                             │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │ AWS KMS  │  │  Azure   │  │ HashiCorp│  │  Google  │  │
│  │          │  │   KV     │  │  Vault   │  │ Cloud KMS│  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                  Storage Layer                              │
│              (Encrypted Database)                           │
│                                                              │
│  • Credentials stored encrypted                            │
│  • Encryption keys never stored in plaintext               │
│  • Audit logs for all operations                           │
└─────────────────────────────────────────────────────────────┘
```

## Encryption

### Envelope Encryption

The Security Vault uses **envelope encryption** for optimal security and performance:

1. **Data Encryption Key (DEK)**: A unique AES-256 key generated for each credential
2. **Master Key**: Stored in KMS, used to encrypt the DEK
3. **Encrypted Credential**: Credential encrypted with DEK
4. **Encrypted DEK**: DEK encrypted with Master Key

**Benefits**:
- Reduced KMS API calls (better performance, lower cost)
- Unique key per credential (better security)
- Fast local encryption/decryption
- Master key never leaves KMS

### AES-256-GCM

**Algorithm**: AES-256-GCM (Galois/Counter Mode)

**Features**:
- **256-bit key**: Industry-standard strong encryption
- **Authenticated encryption**: Detects tampering
- **128-bit authentication tag**: Ensures data integrity
- **Unique IV per encryption**: Prevents pattern analysis

**Implementation**:
```java
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv); // 128-bit auth tag
cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
byte[] ciphertext = cipher.doFinal(plaintext);
```

### Initialization Vector (IV)

- **Length**: 12 bytes (96 bits) - optimal for GCM
- **Generation**: SecureRandom for cryptographic strength
- **Uniqueness**: New IV for every encryption operation
- **Storage**: Stored alongside ciphertext

### Storage Format

Encrypted credentials are stored as:

```
{encryptedDataKey}:{iv}:{ciphertext}:{authTag}
```

Example:
```
AQIDAHi...base64...==:MTIzNDU2Nzg5MDEy:ZW5jcnlwdGVk...==:YXV0aFRhZw==
```

## Key Management

### Master Key

The master key is stored in a KMS provider and **never** leaves the KMS:

- **AWS KMS**: Customer Master Key (CMK)
- **Azure Key Vault**: RSA or AES key
- **HashiCorp Vault**: Transit encryption key
- **Google Cloud KMS**: CryptoKey

### Key Rotation

#### Automatic Rotation

Enable automatic key rotation in your KMS provider:

**AWS KMS**:
```bash
aws kms enable-key-rotation --key-id <key-id>
```

**Azure Key Vault**:
```bash
az keyvault key rotation-policy update \
  --vault-name my-vault \
  --name my-key \
  --value rotation-policy.json
```

#### Manual Rotation

Rotate credentials using the API:

```bash
POST /api/v1/credentials/{id}/rotate
{
  "newValue": "new-secret-value"
}
```

### Key Validation

The system validates keys on startup:

```java
@PostConstruct
public void validateConfiguration() {
    keyManagementPort.validateKey(masterKeyId)
        .subscribe(
            valid -> log.info("Master key validated"),
            error -> log.error("Master key validation failed", error)
        );
}
```

## Access Control

### Authentication

Authentication and authorization are managed by the **Istio service mesh**, not Spring Security directly. The `SecurityConfig` class permits all exchanges and relies on Istio for:

- **mTLS** between services
- **JWT validation**
- **Authorization policies**
- **CORS policies**

Spring Security is configured only for security headers (XSS protection, clickjacking prevention via X-Frame-Options DENY, HSTS) and provides a `BCryptPasswordEncoder(12)` bean for internal use.

```java
// SecurityConfig.java - permits all exchanges, Istio handles auth
.authorizeExchange(exchanges -> exchanges
    .anyExchange().permitAll()
)
```

### Application-Level Access Control

The `AccessControlService` provides application-level access decisions using `AccessRequest` records:

```java
record AccessRequest(String userId, String serviceName, String ipAddress,
    String environment, boolean hasApproval, String reason) {}
record AccessDecision(boolean allowed, String denyReason) {}
```

Access control checks IP whitelisting, service whitelisting, approval requirements for sensitive credentials, and lockout after failed attempts.

### Credential Decryption

Decrypt a credential value with access control and audit logging:

```bash
POST /api/v1/credentials/{id}/decrypt
```

Headers extracted for access control: `X-User-Id`, `X-Forwarded-User`, `X-Source-Service`, `X-Forwarded-Service`, `X-Forwarded-For`.

## Audit Logging

### Audit Events

All operations are logged via `CredentialAuditService`:

- Credential created
- Credential read (access)
- Credential updated
- Credential deleted
- Credential rotated
- Credential decrypted
- Failed access attempts
- Denied access attempts

### Audit Log Format

```json
{
  "id": "audit-log-id",
  "credentialId": "credential-id",
  "action": "READ",
  "userId": "user-123",
  "ipAddress": "192.168.1.100",
  "userAgent": "Mozilla/5.0...",
  "timestamp": "2025-10-31T10:00:00Z",
  "success": true,
  "metadata": {
    "reason": "API access"
  }
}
```

### Audit Log Storage

Audit logs are stored in the `credential_access_logs` table with fields including: `access_type`, `accessed_by`, `accessed_by_user_id`, `accessed_by_service`, `access_ip`, `access_result`, `access_reason`, `decryption_successful`, `error_message`, and `access_duration_ms`.

Note: There is currently no dedicated REST endpoint for querying audit logs. Audit data can be accessed directly from the database.

## Network Security

### TLS/HTTPS

Always use TLS in production:

```yaml
server:
  port: 8443
  ssl:
    enabled: true
    key-store: classpath:keystore.p12
    key-store-password: ${KEYSTORE_PASSWORD}
    key-store-type: PKCS12
```

### Database Encryption

Enable TLS for database connections:

```yaml
spring:
  r2dbc:
    url: r2dbc:postgresql://db.example.com:5432/firefly_vault?sslmode=require
```

## Secrets Management

### Never Hardcode Secrets

**Bad**:
```yaml
firefly:
  security:
    vault:
      encryption:
        master-key-id: arn:aws:kms:us-east-1:123456789012:key/12345678
```

**Good**:
```yaml
firefly:
  security:
    vault:
      encryption:
        master-key-id: ${KMS_MASTER_KEY_ID}
```

### Use Environment Variables

```bash
export KMS_MASTER_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/12345678
export DB_PASSWORD=strong-password-here
```

### Use Secrets Managers

- **AWS**: AWS Secrets Manager or Parameter Store
- **Azure**: Azure Key Vault
- **Kubernetes**: Kubernetes Secrets
- **HashiCorp**: Vault

## Resilience & Security

### Circuit Breaker

Prevents cascading failures when KMS is unavailable. Configured in `ResilienceConfiguration` with:
- 50% failure rate threshold
- 60-second wait duration in open state
- Sliding window of 10 calls, minimum 5 calls
- 3 permitted calls in half-open state

### Rate Limiting

Prevents abuse at two levels:

1. **KMS operations** (Resilience4j): 100 calls per second, configured in `ResilienceConfiguration`
2. **Web layer** (RateLimitingFilter): Configurable per-client rate limiting via:

```yaml
firefly:
  security:
    vault:
      access-control:
        enable-rate-limiting: true
        rate-limit-per-minute: 100
```

### Retry with Backoff

Handles transient KMS failures. Configured in `ResilienceConfiguration` with:
- 3 max attempts
- Exponential backoff starting at 1 second with multiplier of 2.0

## Compliance

### GDPR

- **Right to erasure**: Delete credentials via API
- **Data portability**: Export credentials in JSON format
- **Audit trail**: Complete audit logs

### SOC 2

- **Access control**: RBAC and authentication
- **Encryption**: AES-256-GCM encryption at rest
- **Audit logging**: All operations logged
- **Key rotation**: Automatic and manual rotation

### HIPAA

- **Encryption**: PHI encrypted with AES-256
- **Access logs**: Complete audit trail
- **Key management**: Secure key storage in KMS

## Security Best Practices

### 1. Use Production KMS

Never use IN_MEMORY provider in production:

**Production**: AWS KMS, Azure Key Vault, Google Cloud KMS, HashiCorp Vault  
**Production**: IN_MEMORY

### 2. Enable Key Rotation

Rotate keys regularly:

- **Automatic**: Enable in KMS provider
- **Manual**: Rotate credentials every 90 days

### 3. Least Privilege

Grant minimum required permissions:

```json
{
  "Effect": "Allow",
  "Action": [
    "kms:Encrypt",
    "kms:Decrypt",
    "kms:GenerateDataKey"
  ],
  "Resource": "arn:aws:kms:us-east-1:123456789012:key/*"
}
```

### 4. Monitor and Alert

Set up alerts for:

- Failed encryption/decryption attempts
- Unusual access patterns
- Circuit breaker open
- High error rates

### 5. Regular Audits

Review audit logs regularly via direct database queries on the `credential_access_logs` table or through monitoring dashboards.

## Security Checklist

- [ ] Use production KMS provider (not IN_MEMORY)
- [ ] Enable TLS/HTTPS
- [ ] Use strong authentication
- [ ] Enable audit logging
- [ ] Configure rate limiting
- [ ] Enable circuit breaker
- [ ] Rotate keys regularly
- [ ] Use environment variables for secrets
- [ ] Enable database encryption
- [ ] Set up monitoring and alerts
- [ ] Review audit logs regularly
- [ ] Use least privilege IAM policies
- [ ] Enable automatic key rotation
- [ ] Backup database regularly

## Next Steps

- [Encryption Details](encryption.md)
- [Access Control](access-control.md)
- [Audit & Compliance](audit-compliance.md)
- [Best Practices](best-practices.md)

