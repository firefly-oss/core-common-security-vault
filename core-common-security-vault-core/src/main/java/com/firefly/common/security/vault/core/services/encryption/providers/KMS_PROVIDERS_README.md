# KMS Providers Implementation Guide

This directory contains KMS (Key Management System) provider implementations for the Security Vault.

Note: The actual adapter implementations are located in the `adapters` package:
`core-common-security-vault-core/src/main/java/com/firefly/common/security/vault/core/adapters/`

## Current Status

All providers implement the `KeyManagementPort` interface (not `KmsProvider`).

- **InMemoryKeyManagementAdapter** - Implemented (for development/testing only)
- **AwsKmsKeyManagementAdapter** - Implemented (AWS KMS SDK integration)
- **AzureKeyVaultKeyManagementAdapter** - Implemented (Azure Key Vault SDK integration)
- **HashiCorpVaultKeyManagementAdapter** - Implemented (Vault Transit Engine integration)
- **GoogleCloudKmsKeyManagementAdapter** - Implemented (Google Cloud KMS SDK integration)
- **ResilientKeyManagementAdapter** - Decorator that adds Circuit Breaker, Rate Limiter, and Retry patterns

## Implementation Instructions

### 1. AWS KMS Provider

**Status**: Implemented as `AwsKmsKeyManagementAdapter` in the `adapters` package.

#### Dependencies in `core-common-security-vault-core/pom.xml`:

```xml
<dependency>
    <groupId>software.amazon.awssdk</groupId>
    <artifactId>kms</artifactId>
    <version>2.20.0</version>
</dependency>
<dependency>
    <groupId>software.amazon.awssdk</groupId>
    <artifactId>netty-nio-client</artifactId>
    <version>2.20.0</version>
</dependency>
```

#### Implementation: `AwsKmsKeyManagementAdapter.java`

```java
@Slf4j
@Component
@ConditionalOnProperty(
    prefix = "firefly.security.vault.encryption",
    name = "provider",
    havingValue = "AWS_KMS"
)
public class AwsKmsKeyManagementAdapter implements KeyManagementPort {
    
    private final KmsAsyncClient kmsClient;
    private final SecurityVaultProperties properties;
    
    public AwsKmsProvider(SecurityVaultProperties properties) {
        this.properties = properties;
        this.kmsClient = KmsAsyncClient.builder()
            .region(Region.of(properties.getEncryption().getAwsKms().getRegion()))
            .build();
    }
    
    @Override
    public Mono<KmsEncryptionResult> encrypt(byte[] plaintext, String keyId, String context) {
        return Mono.fromFuture(() -> {
            Map<String, String> encryptionContext = context != null ? 
                Map.of("context", context) : Map.of();
            
            return kmsClient.encrypt(EncryptRequest.builder()
                .keyId(keyId)
                .plaintext(SdkBytes.fromByteArray(plaintext))
                .encryptionContext(encryptionContext)
                .build());
        }).map(response -> new KmsEncryptionResult(
            response.ciphertextBlob().asByteArray(),
            response.keyId(),
            "AWS_KMS_AES_256",
            context
        ));
    }
    
    @Override
    public Mono<byte[]> decrypt(byte[] ciphertext, String keyId, String context) {
        return Mono.fromFuture(() -> {
            Map<String, String> encryptionContext = context != null ? 
                Map.of("context", context) : Map.of();
            
            return kmsClient.decrypt(DecryptRequest.builder()
                .ciphertextBlob(SdkBytes.fromByteArray(ciphertext))
                .encryptionContext(encryptionContext)
                .build());
        }).map(response -> response.plaintext().asByteArray());
    }
    
    @Override
    public Mono<DataKey> generateDataKey(String keyId, String keySpec) {
        return Mono.fromFuture(() -> 
            kmsClient.generateDataKey(GenerateDataKeyRequest.builder()
                .keyId(keyId)
                .keySpec(DataKeySpec.AES_256)
                .build())
        ).map(response -> new DataKey(
            response.plaintext().asByteArray(),
            response.ciphertextBlob().asByteArray(),
            response.keyId()
        ));
    }
    
    @Override
    public Mono<KeyRotationResult> rotateKey(String keyId) {
        return Mono.fromFuture(() ->
            kmsClient.enableKeyRotation(EnableKeyRotationRequest.builder()
                .keyId(keyId)
                .build())
        ).map(response -> new KeyRotationResult(
            true,
            "rotation-enabled",
            "Automatic key rotation enabled"
        )).onErrorResume(e -> Mono.just(new KeyRotationResult(
            false,
            null,
            "Rotation failed: " + e.getMessage()
        )));
    }
    
    @Override
    public Mono<Boolean> validateKey(String keyId) {
        return Mono.fromFuture(() ->
            kmsClient.describeKey(DescribeKeyRequest.builder()
                .keyId(keyId)
                .build())
        ).map(response -> response.keyMetadata().enabled())
         .onErrorReturn(false);
    }
    
    @Override
    public ProviderType getProviderType() {
        return ProviderType.AWS_KMS;
    }
}
```

### 2. Azure Key Vault Provider

**Status**: Implemented as `AzureKeyVaultKeyManagementAdapter` in the `adapters` package.

#### Dependencies:

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

#### Implementation: `AzureKeyVaultKeyManagementAdapter.java`

```java
@Slf4j
@Component
@ConditionalOnProperty(
    prefix = "firefly.security.vault.encryption",
    name = "provider",
    havingValue = "AZURE_KEY_VAULT"
)
public class AzureKeyVaultKeyManagementAdapter implements KeyManagementPort {
    
    private final CryptographyAsyncClient cryptoClient;
    private final SecurityVaultProperties properties;
    
    public AzureKeyVaultProvider(SecurityVaultProperties properties) {
        this.properties = properties;
        var config = properties.getEncryption().getAzureKeyVault();
        
        ClientSecretCredential credential = new ClientSecretCredentialBuilder()
            .tenantId(config.getTenantId())
            .clientId(config.getClientId())
            .clientSecret(config.getClientSecret())
            .build();
        
        KeyAsyncClient keyClient = new KeyClientBuilder()
            .vaultUrl(config.getVaultUrl())
            .credential(credential)
            .buildAsyncClient();
        
        this.cryptoClient = keyClient.getCryptographyAsyncClient(config.getKeyName());
    }
    
    @Override
    public Mono<KmsEncryptionResult> encrypt(byte[] plaintext, String keyId, String context) {
        return Mono.fromFuture(
            cryptoClient.encrypt(EncryptionAlgorithm.A256GCM, plaintext).toFuture()
        ).map(result -> new KmsEncryptionResult(
            result.getCipherText(),
            keyId,
            "A256GCM",
            context
        ));
    }
    
    // Implement other methods similarly...
    
    @Override
    public ProviderType getProviderType() {
        return ProviderType.AZURE_KEY_VAULT;
    }
}
```

### 3. HashiCorp Vault Provider

**Status**: Implemented as `HashiCorpVaultKeyManagementAdapter` in the `adapters` package.

#### Dependencies:

```xml
<dependency>
    <groupId>com.bettercloud</groupId>
    <artifactId>vault-java-driver</artifactId>
    <version>5.1.0</version>
</dependency>
```

#### Implementation: `HashiCorpVaultKeyManagementAdapter.java`

```java
@Slf4j
@Component
@ConditionalOnProperty(
    prefix = "firefly.security.vault.encryption",
    name = "provider",
    havingValue = "HASHICORP_VAULT"
)
public class HashiCorpVaultKeyManagementAdapter implements KeyManagementPort {
    
    private final Vault vault;
    
    public HashiCorpVaultProvider(SecurityVaultProperties properties) {
        // Initialize Vault client
        VaultConfig config = new VaultConfig()
            .address(properties.getEncryption().getHashicorpVault().getAddress())
            .token(properties.getEncryption().getHashicorpVault().getToken())
            .build();
        
        this.vault = new Vault(config);
    }
    
    // Implement KmsProvider methods using Vault Transit engine
    
    @Override
    public ProviderType getProviderType() {
        return ProviderType.HASHICORP_VAULT;
    }
}
```

## Configuration

Update `application.yaml` to select the KMS provider:

```yaml
firefly:
  security:
    vault:
      encryption:
        provider: AWS_KMS  # Options: IN_MEMORY, AWS_KMS, AZURE_KEY_VAULT, HASHICORP_VAULT, GOOGLE_CLOUD_KMS

        aws-kms:
          region: us-east-1
          key-arn: arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012

        azure-key-vault:
          vault-url: https://my-vault.vault.azure.net/
          key-name: my-encryption-key
          tenant-id: ${AZURE_TENANT_ID}
          client-id: ${AZURE_CLIENT_ID}
          client-secret: ${AZURE_CLIENT_SECRET}
```

Note: The `kms-provider` property is deprecated. Use `provider` instead.

## Testing

Each provider should have corresponding integration tests using:
- **AWS**: LocalStack or AWS SDK mocks
- **Azure**: Azure SDK test containers
- **HashiCorp**: Vault test container

## Security Considerations

1. **Never commit credentials** - Use environment variables or secret managers
2. **Use IAM roles** when possible (AWS)
3. **Enable key rotation** for all production keys
4. **Monitor KMS usage** for anomalies
5. **Implement circuit breakers** for KMS calls
6. **Cache decrypted keys** appropriately (with TTL)

## Production Checklist

- [x] Add appropriate KMS SDK dependencies
- [x] Implement adapter classes with all `KeyManagementPort` interface methods
- [ ] Add integration tests
- [ ] Configure proper IAM/RBAC permissions
- [ ] Enable key rotation policies
- [ ] Set up monitoring and alerting
- [ ] Document key management procedures
- [ ] Implement key backup/recovery procedures

