package stirling.software.proprietary.storage.crypto;

import java.util.Optional;

/**
 * Always-present holder for the (conditionally created) storage-encryption machinery. The key
 * service and master key only exist when encryption is enabled or encrypted content already exists
 * — creating them eagerly would generate a key file for installs that never use the feature — but
 * the admin API and migration job need a stable bean to inject regardless.
 */
public class StorageEncryptionState {

    public static final StorageEncryptionState INACTIVE =
            new StorageEncryptionState(false, null, StorageEncryptionAuditListener.NOOP);

    private final boolean writeEnabled;
    private final FileEncryptionKeyService keyService;
    private final StorageEncryptionAuditListener auditListener;

    public StorageEncryptionState(
            boolean writeEnabled,
            FileEncryptionKeyService keyService,
            StorageEncryptionAuditListener auditListener) {
        this.writeEnabled = writeEnabled;
        this.keyService = keyService;
        this.auditListener = auditListener;
    }

    public StorageEncryptionAuditListener auditListener() {
        return auditListener;
    }

    /** True when new writes are encrypted (flag on + licence passed). */
    public boolean isWriteEnabled() {
        return writeEnabled;
    }

    /** True when the crypto machinery exists (write-enabled or decrypt-only mode). */
    public boolean isActive() {
        return keyService != null;
    }

    public Optional<FileEncryptionKeyService> keyService() {
        return Optional.ofNullable(keyService);
    }
}
