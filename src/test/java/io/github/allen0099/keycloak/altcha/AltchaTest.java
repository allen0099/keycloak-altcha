package io.github.allen0099.keycloak.altcha;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
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
    void externalModeNeedsBothAServerUrlAndASecret() {
        assertFalse(AltchaStep.external(null));
        assertFalse(AltchaStep.external(new AltchaConfigModelStub(Map.of(
                AltchaStep.SERVER_URL, "https://sentinel.example.com/v1/challenge"))));
        assertFalse(AltchaStep.external(new AltchaConfigModelStub(Map.of(
                AltchaStep.SECRET, "sec_test"))));
        assertTrue(AltchaStep.external(new AltchaConfigModelStub(Map.of(
                AltchaStep.SERVER_URL, "https://sentinel.example.com/v1/challenge",
                AltchaStep.SECRET, "sec_test"))));
    }

    @Test
    void apiKeyIsAddedToTheServerUrlOnlyWhenItHasNone() {
        assertEquals("https://sentinel.example.com/v1/challenge?apiKey=key_1",
                AltchaServer.challengeUrl(" https://sentinel.example.com/v1/challenge ", "key_1"));
        assertEquals("https://sentinel.example.com/v1/challenge?x=1&apiKey=key_1",
                AltchaServer.challengeUrl("https://sentinel.example.com/v1/challenge?x=1", "key_1"));
        assertEquals("https://sentinel.example.com/v1/challenge?apiKey=key_2",
                AltchaServer.challengeUrl("https://sentinel.example.com/v1/challenge?apiKey=key_2", "key_1"));
        assertEquals("https://sentinel.example.com/v1/challenge",
                AltchaServer.challengeUrl("https://sentinel.example.com/v1/challenge", ""));
    }

    @Test
    void sentinelPayloadVerifiesOnlyWithItsSecretAndBeforeExpiry() throws Exception {
        String secret = "sec_test";
        String verificationData = "verified=true&expire=" + (NOW + 60) + "&score=90";
        String payload = sentinelPayload(secret, "SHA-256", verificationData, true);

        assertTrue(AltchaServer.verify(payload, secret, NOW));
        assertFalse(AltchaServer.verify(payload, "other", NOW), "wrong secret");
        assertTrue(AltchaServer.verify(payload, secret, NOW + 60), "still valid at expire");
        assertFalse(AltchaServer.verify(payload, secret, NOW + 61), "expired");
        assertFalse(AltchaServer.verify(sentinelPayload(secret, "SHA-256", verificationData, false), secret, NOW),
                "payload not marked verified");

        JsonNode changed = decode(payload);
        ((com.fasterxml.jackson.databind.node.ObjectNode) changed)
                .put("verificationData", verificationData.replace("score=90", "score=99"));
        String tampered = Base64.getEncoder().encodeToString(JSON.writeValueAsBytes(changed));
        assertFalse(AltchaServer.verify(tampered, secret, NOW), "tampered verification data");
        assertFalse(AltchaServer.verify(null, secret, NOW));
        assertFalse(AltchaServer.verify(payload, "", NOW));
    }

    @Test
    void sentinelPayloadSupportsSha1() throws Exception {
        String secret = "sec_test";
        String verificationData = "verified=true&expire=" + (NOW + 60);
        assertTrue(AltchaServer.verify(sentinelPayload(secret, "SHA-1", verificationData, true), secret, NOW));
    }

    @Test
    void replayKeyIgnoresUnrelatedJsonChanges() throws Exception {
        String secret = "sec_test";
        String payload = sentinelPayload(secret, "SHA-256", "verified=true&expire=" + (NOW + 60), true);
        JsonNode changed = decode(payload);
        ((com.fasterxml.jackson.databind.node.ObjectNode) changed).put("unused", "junk");
        String reencoded = Base64.getEncoder().encodeToString(JSON.writeValueAsBytes(changed));
        assertEquals(AltchaServer.replayKey(payload), AltchaServer.replayKey(reencoded));
    }

    @Test
    void signedChallengeFromAnExternalServerVerifiesItsProofOfWork() throws Exception {
        String secret = "hmac_test";
        String nonce = "00112233445566778899aabbccddeeff";
        String salt = "ffeeddccbbaa99887766554433221100";
        Map<String, Object> parameters = new java.util.TreeMap<>();
        parameters.put("algorithm", "SHA-256");
        parameters.put("nonce", nonce);
        parameters.put("salt", salt);
        parameters.put("cost", 1);
        parameters.put("keyLength", 32);
        parameters.put("keyPrefix", "00");
        parameters.put("expiresAt", NOW + 60);
        String canonical = JSON.writeValueAsString(parameters);
        assertEquals(canonical, AltchaServer.canonicalJson(JSON.readTree(canonical)));
        String signature = hmacHex("SHA-256", canonical.getBytes(StandardCharsets.UTF_8), secret);

        byte[] nonceBytes = HEX.parseHex(nonce);
        byte[] saltBytes = HEX.parseHex(salt);
        String derivedKey = null;
        long counter = -1;
        for (long c = 0; derivedKey == null; c++) {
            String key = HEX.formatHex(Altcha.deriveKey(nonceBytes, saltBytes, c, 1));
            if (key.startsWith("00")) {
                derivedKey = key;
                counter = c;
            }
        }
        String payload = Base64.getEncoder().encodeToString(("{\"challenge\":{\"parameters\":" + canonical
                + ",\"signature\":\"" + signature + "\"},"
                + "\"solution\":{\"counter\":" + counter + ",\"derivedKey\":\"" + derivedKey + "\"}}")
                .getBytes(StandardCharsets.UTF_8));

        assertTrue(AltchaServer.verify(payload, secret, NOW));
        assertFalse(AltchaServer.verify(payload, "other", NOW), "wrong secret");
        assertFalse(AltchaServer.verify(payload, secret, NOW + 61), "expired");
        JsonNode tampered = decode(payload);
        ((com.fasterxml.jackson.databind.node.ObjectNode)
                        tampered.path("challenge").path("parameters"))
                .put("cost", 2);
        assertFalse(AltchaServer.verify(
                        Base64.getEncoder().encodeToString(JSON.writeValueAsBytes(tampered)), secret, NOW),
                "tampered parameters");
    }

    static String sentinelPayload(String secret, String algorithm, String verificationData, boolean verified)
            throws Exception {
        byte[] digest = MessageDigest.getInstance(algorithm).digest(verificationData.getBytes(StandardCharsets.UTF_8));
        String json = "{\"algorithm\":\"" + algorithm + "\",\"verified\":" + verified
                + ",\"signature\":\"" + hmacHex(algorithm, digest, secret) + "\","
                + "\"verificationData\":\"" + verificationData + "\"}";
        return Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    static String hmacHex(String algorithm, byte[] data, String secret) throws Exception {
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("Hmac" + algorithm.replace("-", ""));
        mac.init(new javax.crypto.spec.SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), mac.getAlgorithm()));
        return HEX.formatHex(mac.doFinal(data));
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
