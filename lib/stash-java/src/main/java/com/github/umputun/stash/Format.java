package com.github.umputun.stash;

import com.google.gson.annotations.SerializedName;

/**
 * Supported value formats for syntax highlighting in the web UI.
 */
public enum Format {
    @SerializedName("text")
    TEXT("text"),

    @SerializedName("json")
    JSON("json"),

    @SerializedName("yaml")
    YAML("yaml"),

    @SerializedName("xml")
    XML("xml"),

    @SerializedName("toml")
    TOML("toml"),

    @SerializedName("ini")
    INI("ini"),

    @SerializedName("hcl")
    HCL("hcl"),

    @SerializedName("shell")
    SHELL("shell");

    private final String value;

    Format(String value) {
        this.value = value;
    }

    /**
     * Returns the string value used in HTTP headers and JSON.
     *
     * @return the format string value
     */
    public String getValue() {
        return value;
    }

    /**
     * Parses a string value to Format enum.
     *
     * @param value the string value
     * @return the corresponding Format, or TEXT if not found
     */
    public static Format fromValue(String value) {
        if (value == null) {
            return TEXT;
        }
        for (Format format : values()) {
            if (format.value.equalsIgnoreCase(value)) {
                return format;
            }
        }
        return TEXT;
    }

    @Override
    public String toString() {
        return value;
    }
}
