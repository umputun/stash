package io.github.umputun.stash;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

class FormatTest {

    @Test
    void allFormatsHaveCorrectValues() {
        assertThat(Format.TEXT.getValue()).isEqualTo("text");
        assertThat(Format.JSON.getValue()).isEqualTo("json");
        assertThat(Format.YAML.getValue()).isEqualTo("yaml");
        assertThat(Format.XML.getValue()).isEqualTo("xml");
        assertThat(Format.TOML.getValue()).isEqualTo("toml");
        assertThat(Format.INI.getValue()).isEqualTo("ini");
        assertThat(Format.HCL.getValue()).isEqualTo("hcl");
        assertThat(Format.SHELL.getValue()).isEqualTo("shell");
    }

    @ParameterizedTest
    @CsvSource({
            "text, TEXT",
            "json, JSON",
            "yaml, YAML",
            "xml, XML",
            "toml, TOML",
            "ini, INI",
            "hcl, HCL",
            "shell, SHELL",
            "TEXT, TEXT",
            "JSON, JSON",
            "Json, JSON"
    })
    void fromValueParsesCorrectly(String input, Format expected) {
        assertThat(Format.fromValue(input)).isEqualTo(expected);
    }

    @Test
    void fromValueReturnsTextForUnknown() {
        assertThat(Format.fromValue("unknown")).isEqualTo(Format.TEXT);
        assertThat(Format.fromValue("")).isEqualTo(Format.TEXT);
        assertThat(Format.fromValue(null)).isEqualTo(Format.TEXT);
    }

    @Test
    void toStringReturnsValue() {
        assertThat(Format.JSON.toString()).isEqualTo("json");
    }
}
