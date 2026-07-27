package stirling.software.proprietary.storage.config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import stirling.software.common.configuration.InstallationPathConfig;
import stirling.software.common.model.ApplicationProperties;
import stirling.software.proprietary.cluster.s3.S3Clients;
import stirling.software.proprietary.security.configuration.ee.LicenseKeyChecker;
import stirling.software.proprietary.service.AuditService;
import stirling.software.proprietary.storage.crypto.AuditingStorageEncryptionListener;
import stirling.software.proprietary.storage.crypto.EncryptingStorageProvider;
import stirling.software.proprietary.storage.crypto.FileEncryptionKeyService;
import stirling.software.proprietary.storage.crypto.FileEncryptionMasterKey;
import stirling.software.proprietary.storage.crypto.StorageEncryptionAuditListener;
import stirling.software.proprietary.storage.crypto.StorageEncryptionState;
import stirling.software.proprietary.storage.provider.DatabaseStorageProvider;
import stirling.software.proprietary.storage.provider.LocalStorageProvider;
import stirling.software.proprietary.storage.provider.S3StorageProvider;
import stirling.software.proprietary.storage.provider.StorageProvider;
import stirling.software.proprietary.storage.repository.FileEncryptionKeyRepository;
import stirling.software.proprietary.storage.repository.StoredFileBlobRepository;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class StorageProviderConfig {

    private final ApplicationProperties applicationProperties;
    private final StoredFileBlobRepository storedFileBlobRepository;
    private final FileEncryptionKeyRepository fileEncryptionKeyRepository;
    private final LicenseKeyChecker licenseKeyChecker;
    private final AuditService auditService;

    @Value("${stirling.security.fileEncryptionKey:}")
    private String configuredFileEncryptionKey;

    /** Outgoing master key, set only while a rotation is in progress. */
    @Value("${stirling.security.fileEncryptionKeyPrevious:}")
    private String previousFileEncryptionKey;

    /**
     * Admin-bumped on master rotation; rows below this version get re-wrapped by /master/rotate.
     */
    @Value("${stirling.security.fileEncryptionKeyVersion:1}")
    private int fileEncryptionKeyVersion;

    @Value("${cluster.enabled:false}")
    private boolean clusterEnabled;

    /**
     * Builds the (conditionally active) encryption machinery once, shared by the storage decorator
     * and the admin API so kill-switch cache invalidation hits the caches the decorator reads. The
     * write side is gated on the config flag (plus Pro/Enterprise licence); the decrypt side
     * activates whenever encryption keys exist, so switching the flag off — or a lapsed licence —
     * never makes previously encrypted files unreadable.
     */
    @Bean
    public StorageEncryptionState storageEncryptionState() {
        boolean writeEnabled = applicationProperties.getStorage().getEncryption().isEnabled();
        boolean hasEncryptedContent = fileEncryptionKeyRepository.count() > 0;
        if (!writeEnabled && !hasEncryptedContent) {
            return StorageEncryptionState.INACTIVE;
        }
        if (writeEnabled) {
            licenseKeyChecker.requireProOrEnterprise("storage.encryption");
        }
        FileEncryptionMasterKey masterKey =
                new FileEncryptionMasterKey(
                        configuredFileEncryptionKey,
                        previousFileEncryptionKey,
                        fileEncryptionKeyVersion,
                        clusterEnabled);
        StorageEncryptionAuditListener listener =
                new AuditingStorageEncryptionListener(
                        auditService,
                        applicationProperties.getStorage().getEncryption().isAuditReads());
        FileEncryptionKeyService keyService =
                new FileEncryptionKeyService(fileEncryptionKeyRepository, masterKey, listener);
        // Wrong key must fail startup, not silently start a second key hierarchy.
        keyService.verifyMasterKey();
        log.info(
                "Storage encryption at rest active (writes {})",
                writeEnabled ? "encrypted" : "plaintext; decrypt-only mode");
        return new StorageEncryptionState(writeEnabled, keyService, listener);
    }

    @Bean(destroyMethod = "close")
    public StorageProvider storageProvider(StorageEncryptionState encryptionState) {
        StorageProvider inner = innerStorageProvider();
        if (!encryptionState.isActive()) {
            return inner;
        }
        return new EncryptingStorageProvider(
                inner,
                encryptionState.keyService().orElseThrow(),
                encryptionState.isWriteEnabled(),
                encryptionState.auditListener());
    }

    private StorageProvider innerStorageProvider() {
        boolean storageEnabled = applicationProperties.getStorage().isEnabled();
        String providerName =
                Optional.ofNullable(applicationProperties.getStorage().getProvider())
                        .orElse("local")
                        .trim()
                        .toLowerCase(Locale.ROOT);
        if ("database".equals(providerName)) {
            licenseKeyChecker.requireProOrEnterprise("storage.provider=database");
            return new DatabaseStorageProvider(storedFileBlobRepository);
        }
        if ("s3".equals(providerName)) {
            licenseKeyChecker.requireProOrEnterprise("storage.provider=s3");
            return buildS3Provider(applicationProperties.getStorage().getS3());
        }
        if (!"local".equals(providerName)) {
            throw new IllegalStateException("Storage provider not supported: " + providerName);
        }
        String basePathValue = applicationProperties.getStorage().getLocal().getBasePath();
        if (basePathValue == null || basePathValue.isBlank()) {
            if (storageEnabled) {
                throw new IllegalStateException("Storage base path is not configured");
            }
            basePathValue = InstallationPathConfig.getPath() + "storage";
        }
        Path basePath = Path.of(basePathValue).toAbsolutePath().normalize();
        Path installRoot = Path.of(InstallationPathConfig.getPath()).toAbsolutePath().normalize();
        if (!basePath.startsWith(installRoot)) {
            // Warn rather than hard-fail: admins may legitimately point storage at an external
            // volume, but an unexpected path could indicate a misconfiguration or traversal
            // attempt.
            log.warn(
                    "Storage basePath '{}' is outside the installation directory '{}'. "
                            + "Verify this is intentional.",
                    basePath,
                    installRoot);
        }
        if (storageEnabled) {
            try {
                Files.createDirectories(basePath);
            } catch (IOException e) {
                throw new IllegalStateException(
                        "Unable to create storage base directory: " + basePath, e);
            }
        }
        return new LocalStorageProvider(basePath);
    }

    private S3StorageProvider buildS3Provider(ApplicationProperties.Storage.S3 cfg) {
        S3Clients.Bundle bundle = S3Clients.build(cfg, "storage provider");
        return new S3StorageProvider(bundle.client(), bundle.presigner(), cfg.getBucket());
    }
}
