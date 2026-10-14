package io.github.allen0099.keycloak.altcha;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HexFormat;
import java.io.InputStreamReader;
import java.util.Map;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.keycloak.models.AuthenticatorConfigModel;

class AltchaTest {

    static final long NOW = 1_000_000;
    static final ObjectMapper JSON = new ObjectMapper();
    static final HexFormat HEX = HexFormat.of();

    /** Solve like the widget does, from the challenge JSON alone. */
    static String solve(String challengeJson) throws Exception {
        JsonNode p = JSON.readTree(challengeJson).path("parameters");
        byte[] nonce = HEX.parseHex(p.path("nonce").asText());
        byte[] salt = HEX.parseHex(p.path("salt").asText());
        for (long c = 0; ; c++) {
            String key = HEX.formatHex(Altcha.deriveKey(nonce, salt, c, p.path("cost").asInt()));
            if (key.startsWith(p.path("keyPrefix").asText())) {
                return payload(p.path("nonce").asText(), c, key);
            }
        }
    }

    static String payload(String nonce, long counter, String key) {
        String json = "{\"challenge\":{\"parameters\":{\"nonce\":\"" + nonce + "\"}},"
                + "\"solution\":{\"counter\":" + counter + ",\"derivedKey\":\"" + key + "\"}}";
        return Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    static JsonNode decode(String payload) throws Exception {
        return JSON.readTree(Base64.getDecoder().decode(payload));
    }

    @Test
    void solutionVerifiesOnlyForItsOwnChallengeAndBeforeExpiry() throws Exception {
        Altcha.Settings settings = new Altcha.Settings(3, 2, 60);
        Altcha.Issued issued = Altcha.issue(settings, NOW);
        String answer = solve(issued.challengeJson());

        assertTrue(Altcha.verify(issued.record(), answer, NOW + 60));
        assertFalse(Altcha.verify(issued.record(), answer, NOW + 61), "expired");
        assertFalse(Altcha.verify(Altcha.issue(settings, NOW).record(), answer, NOW), "another challenge");
        assertFalse(Altcha.verify(null, answer, NOW), "nothing issued");
        assertFalse(Altcha.verify(issued.record(), "not base64!", NOW), "garbage");

        JsonNode s = decode(answer);
        String nonce = s.path("challenge").path("parameters").path("nonce").asText();
        long counter = s.path("solution").path("counter").asLong();
        String key = s.path("solution").path("derivedKey").asText();
        assertFalse(Altcha.verify(issued.record(), payload(nonce, counter + 1, key), NOW), "wrong counter");
    }

    @Test
    void settingsFallBackToDefaultsWhenMissingOrOutOfRange() {
        assertEquals(Altcha.Settings.DEFAULT, AltchaStep.settings(null));
        assertTrue(AltchaStep.enabled(null));

        AltchaConfigModelStub config = new AltchaConfigModelStub(Map.of(
                AltchaStep.ENABLED, "false",
                AltchaStep.DIFFICULTY, "5",
                AltchaStep.COST, "50",
                AltchaStep.TTL, "abc"));
        assertFalse(AltchaStep.enabled(config));
        assertEquals(new Altcha.Settings(4, 50, 600), AltchaStep.settings(config));
    }

    @Test
    void everyMessageKeyIsBundledInEnglishAndTraditionalChinese() throws Exception {
        for (String locale : new String[] {"en", "zh_TW"}) {
            Properties bundle = new Properties();
            String path = "/theme-resources/messages/messages_" + locale + ".properties";
            try (var in = new InputStreamReader(AltchaTest.class.getResourceAsStream(path), StandardCharsets.UTF_8)) {
                bundle.load(in);
            }
            assertTrue(bundle.containsKey(AltchaStep.ERROR_MESSAGE), locale);
            for (var property : AltchaStep.CONFIG_PROPERTIES) {
                assertTrue(bundle.containsKey(property.getLabel()), locale + " " + property.getLabel());
                assertTrue(bundle.containsKey(property.getHelpText()), locale + " " + property.getHelpText());
            }
        }
    }

    static final class AltchaConfigModelStub extends AuthenticatorConfigModel {
        AltchaConfigModelStub(Map<String, String> values) {
            setConfig(values);
        }
    }
}
