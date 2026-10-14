package io.github.allen0099.keycloak.altcha;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;

/**
 * ALTCHA v2 proof-of-work challenges (algorithm SHA-256, uint32 counter), as solved by the
 * {@code altcha} widget 3.x.
 *
 * <p>The server keeps what it issued (the {@link Issued#record()}) and checks the solution against
 * that record, so challenges need no HMAC signature and therefore no secret key. Where the record
 * lives is the caller's business: the authenticators keep it in the authentication session; a
 * future REST endpoint (e.g. for a registration API) could keep it in Keycloak's
 * single-use object store. This class depends on neither.
 */
public final class Altcha {

    /** Name of the hidden form field the widget submits its payload in. */
    public static final String FORM_FIELD = "altcha";

    /**
     * Difficulty and lifetime of a challenge.
     *
     * @param difficulty number of leading zero hex digits the derived key must have (each digit
     *     multiplies the expected work by 16)
     * @param cost SHA-256 iterations per attempt
     * @param ttlSeconds how long an issued challenge stays valid
     */
    public record Settings(int difficulty, int cost, long ttlSeconds) {
        public static final Settings DEFAULT = new Settings(4, 1, 600);

        String keyPrefix() {
            return "0".repeat(difficulty);
        }
    }

    /**
     * @param challengeJson what the widget's {@code challenge} attribute takes
     * @param record what the server keeps to verify the answer; opaque to callers
     */
    public record Issued(String challengeJson, String record) {}

    private static final int KEY_LENGTH = 32;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HexFormat HEX = HexFormat.of();

    private Altcha() {}

    public static Issued issue(Settings settings, long nowSeconds) {
        String nonce = randomHex();
        String salt = randomHex();
        long expiresAt = nowSeconds + settings.ttlSeconds();
        Map<String, Object> parameters = Map.of(
                "algorithm", "SHA-256",
                "nonce", nonce,
                "salt", salt,
                "cost", settings.cost(),
                "keyLength", KEY_LENGTH,
                "keyPrefix", settings.keyPrefix(),
                "expiresAt", expiresAt);
        String json;
        try {
            json = JSON.writeValueAsString(Map.of("parameters", parameters));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        // the record carries the settings in force at issue time, so changing them never breaks
        // a page that is already open
        String record = String.join(":", nonce, salt, Long.toString(expiresAt), settings.keyPrefix(),
                Integer.toString(settings.cost()));
        return new Issued(json, record);
    }

    /** True only for a correct, unexpired solution to the challenge described by {@code record}. */
    public static boolean verify(String record, String payload, long nowSeconds) {
        if (record == null || payload == null || payload.isBlank()) {
            return false;
        }
        try {
            String[] r = record.split(":");
            String nonce = r[0];
            String salt = r[1];
            long expiresAt = Long.parseLong(r[2]);
            String keyPrefix = r[3];
            int cost = Integer.parseInt(r[4]);
            if (nowSeconds > expiresAt) {
                return false;
            }
            JsonNode root = JSON.readTree(Base64.getDecoder().decode(payload));
            // parameters echoed by the client are ignored except to match the nonce we issued
            if (!nonce.equals(root.path("challenge").path("parameters").path("nonce").asText())) {
                return false;
            }
            JsonNode solution = root.path("solution");
            long counter = solution.path("counter").asLong(-1);
            if (counter < 0 || counter > 0xFFFFFFFFL) {
                return false;
            }
            String key = HEX.formatHex(deriveKey(HEX.parseHex(nonce), HEX.parseHex(salt), counter, cost));
            return key.startsWith(keyPrefix)
                    && MessageDigest.isEqual(
                            key.getBytes(StandardCharsets.US_ASCII),
                            solution.path("derivedKey").asText().getBytes(StandardCharsets.US_ASCII));
        } catch (Exception e) {
            return false;
        }
    }

    /** Same derivation as the widget: SHA-256^cost(salt || nonce || uint32be(counter)). */
    static byte[] deriveKey(byte[] nonce, byte[] salt, long counter, int cost) throws NoSuchAlgorithmException {
        byte[] key = ByteBuffer.allocate(salt.length + nonce.length + 4)
                .put(salt).put(nonce).putInt((int) counter).array();
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        for (int i = 0; i < Math.max(1, cost); i++) {
            key = sha.digest(key);
        }
        return Arrays.copyOf(key, Math.min(KEY_LENGTH, key.length));
    }

    private static String randomHex() {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        return HEX.formatHex(bytes);
    }
}
