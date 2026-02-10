# Configuration Guide

## Overview

The Firefly Security Vault supports multiple Key Management Service (KMS) providers. You can switch between providers by changing the configuration without modifying code.

## Supported Providers

| Provider | Status | Use Case | Guide |
|----------|--------|----------|-------|
| **In-Memory** | Production-Ready | Development, Testing | [Guide](in-memory.md) |
| **AWS KMS** | Production-Ready | AWS Cloud | [Guide](aws-kms.md) |
| **Azure Key Vault** | Production-Ready | Azure Cloud | [Guide](azure-key-vault.md) |
| **HashiCorp Vault** | Production-Ready | On-Premise, Hybrid | [Guide](hashicorp-vault.md) |
| **Google Cloud KMS** | Production-Ready | Google Cloud | [Guide](google-cloud-kms.md) |

## Quick Start

### 1. Choose Your Provider

Select the appropriate provider based on your deployment environment:

- **Local Development**: Use In-Memory provider
- **AWS Deployment**: Use AWS KMS
- **Azure Deployment**: Use Azure Key Vault
- **On-Premise**: Use HashiCorp Vault
- **GCP Deployment**: Use Google Cloud KMS

### 2. Configure application.yaml

Add the provider configuration to your `application.yaml`:

```yaml
firefly:
  security:
    vault:
      encryption:
        provider: AWS_KMS  # Change this to your provider
        master-key-id: your-key-id
```

### 3. Add Dependencies (Production Only)

For production providers, add the appropriate SDK dependency to your `pom.xml`:

**AWS KMS**:
```xml
<dependency>
    <groupId>software.amazon.awssdk</groupId>
    <artifactId>kms</artifactId>
    <version>2.20.0</version>
</dependency>
```

**Azure Key Vault**:
```xml
<dependency>
    <groupId>com.azure</groupId>
    <artifactId>azure-security-keyvault-keys</artifactId>
    <version>4.6.0</version>
</dependency>
<dependency>
    <groupId>com.azure</groupId>
    <artifactId>azure-identity</artifactId>
    <version>1.10.0</version>
</dependency>
```

**HashiCorp Vault**:
```xml
<dependency>
    <groupId>com.bettercloud</groupId>
    <artifactId>vault-java-driver</artifactId>
    <version>6.1.0</version>
</dependency>
```

**Google Cloud KMS**:
```xml
<dependency>
    <groupId>com.google.cloud</groupId>
    <artifactId>google-cloud-kms</artifactId>
    <version>2.20.0</version>
</dependency>
```

## Configuration Properties

### Common Properties

These properties apply to all providers:

```yaml
firefly:
  security:
    vault:
      encryption:
        # Provider type (required)
        provider: IN_MEMORY  # IN_MEMORY, AWS_KMS, AZURE_KEY_VAULT, HASHICORP_VAULT, GOOGLE_CLOUD_KMS

        # Master key identifier (required)
        master-key-id: default-master-key

        # Encryption algorithm (optional, default: AES-256-GCM)
        algorithm: AES-256-GCM

        # Enable envelope encryption (optional, default: false)
        envelope-encryption: false

      # Rotation configuration (separate section from encryption)
      rotation:
        # Enable automatic rotation (optional, default: false)
        auto-rotation-enabled: false

        # Default rotation interval in days (optional, default: 90)
        default-rotation-days: 90

        # Warning period before expiration in days (optional, default: 7)
        warning-before-days: 7

        # Maximum versions to keep per credential (optional, default: 10)
        max-versions-to-keep: 10
```

### Resilience Configuration

Resilience patterns (Circuit Breaker, Rate Limiter, Retry) are configured via the `ResilienceConfiguration` bean in the `core` module with hardcoded defaults. These are **not** configurable via `application.yaml` properties.

**Default resilience settings** (defined in `ResilienceConfiguration.java`):

- **Circuit Breaker**: 50% failure rate threshold, 60s wait in open state, sliding window of 10 calls, minimum 5 calls, 3 permitted calls in half-open state
- **Rate Limiter**: 100 calls per 1-second period, 5-second timeout
- **Retry**: 3 max attempts, exponential backoff starting at 1s with multiplier of 2.0

The `ResilientKeyManagementAdapter` wraps any `KeyManagementPort` implementation with these resilience patterns applied in order: Retry, Rate Limiter, Circuit Breaker.

### Access Control Configuration

Rate limiting for the web layer is configurable:

```yaml
firefly:
  security:
    vault:
      access-control:
        # Enable rate limiting (optional, default: true)
        enable-rate-limiting: true

        # Requests per minute per client (optional, default: 100)
        rate-limit-per-minute: 100
```

## Environment-Specific Configuration

### Development (application-dev.yaml)

```yaml
spring:
  profiles:
    active: dev

firefly:
  security:
    vault:
      encryption:
        provider: IN_MEMORY
        master-key-id: dev-master-key
```

### Staging (application-staging.yaml)

```yaml
spring:
  profiles:
    active: staging

firefly:
  security:
    vault:
      encryption:
        provider: AWS_KMS
        master-key-id: arn:aws:kms:us-east-1:123456789012:key/staging-key
        aws-kms:
          region: us-east-1
```

### Production (application-prod.yaml)

```yaml
spring:
  profiles:
    active: prod

firefly:
  security:
    vault:
      encryption:
        provider: AWS_KMS
        master-key-id: arn:aws:kms:us-east-1:123456789012:key/prod-key
        aws-kms:
          region: us-east-1
```

## Configuration Validation

The Security Vault validates configuration at startup:

**Valid Configuration**:
```
2025-10-31 10:00:00.000  INFO --- SecurityVaultConfigurationValidator : 
Security Vault Configuration Validation: PASSED
Provider: AWS_KMS
Master Key ID: arn:aws:kms:us-east-1:123456789012:key/prod-key
```

**Invalid Configuration**:
```
2025-10-31 10:00:00.000 ERROR --- SecurityVaultConfigurationValidator : 
Security Vault Configuration Validation: FAILED
- Provider is required
- Master Key ID is required for AWS_KMS provider
```

## Switching Providers

To switch from one provider to another:

1. **Update configuration**:
   ```yaml
   firefly:
     security:
       vault:
         encryption:
           provider: AZURE_KEY_VAULT  # Changed from AWS_KMS
   ```

2. **Add new provider dependency** (if not already present)

3. **Restart the application**

4. **Migrate existing credentials** (if needed):
   ```bash
   # Use the credential rotation API to re-encrypt with new provider
   POST /api/v1/credentials/{id}/rotate
   ```

## Troubleshooting

### Provider Not Found

**Error**: `No qualifying bean of type 'KeyManagementPort' available`

**Solution**: Ensure the provider SDK dependency is in your `pom.xml` and the provider name matches exactly.

### Invalid Credentials

**Error**: `Unable to authenticate with KMS provider`

**Solution**: Check your credentials configuration (AWS credentials, Azure service principal, Vault token, etc.)

### Key Not Found

**Error**: `Key not found: {keyId}`

**Solution**: Verify the master-key-id exists in your KMS provider and you have access to it.

## Next Steps

- [In-Memory Provider Guide](in-memory.md)
- [AWS KMS Provider Guide](aws-kms.md)
- [Azure Key Vault Provider Guide](azure-key-vault.md)
- [HashiCorp Vault Provider Guide](hashicorp-vault.md)
- [Google Cloud KMS Provider Guide](google-cloud-kms.md)

