package io.github.umputun.stash;

import com.google.gson.annotations.SerializedName;

import java.time.Instant;
import java.util.Objects;

/**
 * Metadata for a stored key-value pair.
 */
public final class KeyInfo {

    private final String key;
    private final long size;
    private final Format format;
    private final boolean secret;

    @SerializedName("zk_encrypted")
    private final boolean zkEncrypted;

    @SerializedName("created_at")
    private final Instant createdAt;

    @SerializedName("updated_at")
    private final Instant updatedAt;

    /**
     * Creates a new KeyInfo instance.
     *
     * @param key         the key name
     * @param size        the value size in bytes
     * @param format      the value format
     * @param secret      whether the key is stored as a server-side secret
     * @param zkEncrypted whether the value is zero-knowledge encrypted
     * @param createdAt   creation timestamp
     * @param updatedAt   last update timestamp
     */
    public KeyInfo(String key, long size, Format format, boolean secret,
                   boolean zkEncrypted, Instant createdAt, Instant updatedAt) {
        this.key = key;
        this.size = size;
        this.format = format;
        this.secret = secret;
        this.zkEncrypted = zkEncrypted;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    /**
     * Returns the key name.
     *
     * @return the key
     */
    public String getKey() {
        return key;
    }

    /**
     * Returns the value size in bytes.
     *
     * @return the size
     */
    public long getSize() {
        return size;
    }

    /**
     * Returns the value format.
     *
     * @return the format
     */
    public Format getFormat() {
        return format;
    }

    /**
     * Returns whether the key is stored as a server-side secret.
     *
     * @return true if secret
     */
    public boolean isSecret() {
        return secret;
    }

    /**
     * Returns whether the value is zero-knowledge encrypted.
     *
     * @return true if ZK encrypted
     */
    public boolean isZkEncrypted() {
        return zkEncrypted;
    }

    /**
     * Returns the creation timestamp.
     *
     * @return the creation time
     */
    public Instant getCreatedAt() {
        return createdAt;
    }

    /**
     * Returns the last update timestamp.
     *
     * @return the update time
     */
    public Instant getUpdatedAt() {
        return updatedAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KeyInfo keyInfo = (KeyInfo) o;
        return size == keyInfo.size
                && secret == keyInfo.secret
                && zkEncrypted == keyInfo.zkEncrypted
                && Objects.equals(key, keyInfo.key)
                && format == keyInfo.format
                && Objects.equals(createdAt, keyInfo.createdAt)
                && Objects.equals(updatedAt, keyInfo.updatedAt);
    }

    @Override
    public int hashCode() {
        return Objects.hash(key, size, format, secret, zkEncrypted, createdAt, updatedAt);
    }

    @Override
    public String toString() {
        return "KeyInfo{" +
                "key='" + key + '\'' +
                ", size=" + size +
                ", format=" + format +
                ", secret=" + secret +
                ", zkEncrypted=" + zkEncrypted +
                ", createdAt=" + createdAt +
                ", updatedAt=" + updatedAt +
                '}';
    }
}
