package io.github.allen0099.keycloak.altcha;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.math.BigDecimal;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Verification of payloads produced when challenges come from an external ALTCHA server.
 *
 * <p>Two payload shapes are understood:
 *
 * <ul>
 *   <li>ALTCHA Sentinel / Cloud: {@code verificationData} and a {@code signature} over its
 *       digest. Verified with the API key secret as the HMAC key, exactly like
 *       {@code verifyServerSignature} in {@code altcha-lib}.
 *   <li>A custom ALTCHA server that signs challenges with {@code hmacSignatureSecret}: a
 *       {@code challenge.signature} over the canonical JSON of the challenge parameters. The
 *       proof of work is re-derived from those signed parameters.
 * </ul>
 *
 * <p>All checks are cryptographic and local: Keycloak never calls the external server while a
 * form is submitted. Unsigned payloads are rejected, because anyone could forge them.
 */
final class AltchaServer {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HexFormat HEX = HexFormat.of();
    private static final Pattern API_KEY_PARAMETER = Pattern.compile("[?&]apiKey=", Pattern.CASE_INSENSITIVE);
    private static final long MAX_COUNTER = 0xFFFFFFFFL;

    private AltchaServer() {}

    /**
     * Returns the challenge URL the widget should fetch. When {@code apiKey} is set and the URL
     * does not carry one already, it is appended as the {@code apiKey} query parameter.
     */
    static String challengeUrl(String serverUrl, String apiKey) {
        String url = serverUrl.trim();
        if (apiKey == null || apiKey.isBlank() || API_KEY_PARAMETER.matcher(url).find()) {
            return url;
        }
        String separator = !url.contains("?") ? "?" : url.endsWith("?") || url.endsWith("&") ? "" : "&";
        return url + separator + "apiKey=" + URLEncoder.encode(apiKey.trim(), StandardCharsets.UTF_8);
    }

    /** True only for a correctly signed, unexpired payload from the external server. */
    static boolean verify(String payload, String secret, long nowSeconds) {
        if (payload == null || payload.isBlank() || secret == null || secret.isBlank()) {
            return false;
        }
        try {
            JsonNode root = JSON.readTree(Base64.getDecoder().decode(payload));
            if (root == null || !root.isObject()) {
                return false;
            }
            if (root.hasNonNull("verificationData") && root.hasNonNull("signature")) {
                return verifySentinel(root, secret, nowSeconds);
            }
            if (root.path("challenge").hasNonNull("signature")) {
                return verifySignedChallenge(root, secret, nowSeconds);
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /** Stable key for replay protection of a payload, safe to hold in the single-use store. */
    static String fingerprint(String payload) {
        try {
            return HEX.formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(payload.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Replay key derived from the signed part of the payload, not its whole encoding, so
     * reordering outer JSON fields or adding unused ones cannot make an old payload look new.
     */
    static String replayKey(String payload) {
        try {
            JsonNode root = JSON.readTree(Base64.getDecoder().decode(payload));
            String signature = root.path("signature").asText("");
            if (!signature.isEmpty()) {
                return "sentinel:" + signature;
            }
            String challengeSignature = root.path("challenge").path("signature").asText("");
            if (!challengeSignature.isEmpty()) {
                return "challenge:" + challengeSignature;
            }
        } catch (Exception ignored) {
            // fall through to the whole payload
        }
        return "payload:" + fingerprint(payload);
    }

    /** ALTCHA Sentinel / Cloud server signature ({@code verifyServerSignature}). */
    private static boolean verifySentinel(JsonNode root, String secret, long nowSeconds)
            throws GeneralSecurityException {
        String algorithm = root.path("algorithm").asText("");
        if (!isServerAlgorithm(algorithm)) {
            return false;
        }
        String verificationData = root.path("verificationData").asText("");
        String signature = root.path("signature").asText("");
        if (verificationData.isEmpty() || signature.isEmpty()) {
            return false;
        }
        // altcha-lib signs HMAC(algorithm, digest(algorithm, verificationData), secret).
        byte[] digest = MessageDigest.getInstance(algorithm)
                .digest(verificationData.getBytes(StandardCharsets.UTF_8));
        if (!constantTimeEquals(hmacHex(algorithm, digest, secret), signature)) {
            return false;
        }
        if (!root.path("verified").asBoolean(false)) {
            return false;
        }
        Map<String, String> data = parseForm(verificationData);
        if (!"true".equals(data.get("verified"))) {
            return false;
        }
        String expire = data.get("expire");
        return expire == null || expire.isEmpty() || Long.parseLong(expire) >= nowSeconds;
    }

    /** A challenge signed with {@code hmacSignatureSecret} by a custom ALTCHA server. */
    private static boolean verifySignedChallenge(JsonNode root, String secret, long nowSeconds)
            throws Exception {
        JsonNode challenge = root.path("challenge");
        JsonNode parameters = challenge.path("parameters");
        // Only the SHA-256 derivation this project already implements is accepted.
        String algorithm = parameters.path("algorithm").asText("");
        if (!"SHA-256".equals(algorithm)) {
            return false;
        }
        String signature = challenge.path("signature").asText("");
        if (signature.isEmpty()
                || !constantTimeEquals(
                        hmacHex(algorithm, canonicalJson(parameters).getBytes(StandardCharsets.UTF_8), secret),
                        signature)) {
            return false;
        }
        long expiresAt = parameters.path("expiresAt").asLong(0);
        if (expiresAt > 0 && nowSeconds > expiresAt) {
            return false;
        }
        JsonNode solution = root.path("solution");
        long counter = solution.path("counter").asLong(-1);
        if (counter < 0 || counter > MAX_COUNTER) {
            return false;
        }
        byte[] nonce = HEX.parseHex(parameters.path("nonce").asText(""));
        byte[] salt = HEX.parseHex(parameters.path("salt").asText(""));
        String key = HEX.formatHex(Altcha.deriveKey(
                nonce,
                salt,
                counter,
                parameters.path("cost").asInt(1),
                parameters.path("keyLength").asInt(32)));
        return key.startsWith(parameters.path("keyPrefix").asText(""))
                && constantTimeEquals(key, solution.path("derivedKey").asText(""));
    }

    private static boolean isServerAlgorithm(String algorithm) {
        return switch (algorithm) {
            case "SHA-1", "SHA-256", "SHA-384", "SHA-512" -> true;
            default -> false;
        };
    }

    private static String hmacHex(String algorithm, byte[] data, String secret)
            throws GeneralSecurityException {
        Mac mac = Mac.getInstance("Hmac" + algorithm.replace("-", ""));
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), mac.getAlgorithm()));
        return HEX.formatHex(mac.doFinal(data));
    }

    /** Parses {@code application/x-www-form-urlencoded} verification data, first value wins. */
    private static Map<String, String> parseForm(String data) {
        Map<String, String> values = new HashMap<>();
        for (String pair : data.split("&")) {
            int equals = pair.indexOf('=');
            if (equals < 0) {
                continue;
            }
            values.putIfAbsent(
                    URLDecoder.decode(pair.substring(0, equals), StandardCharsets.UTF_8),
                    URLDecoder.decode(pair.substring(equals + 1), StandardCharsets.UTF_8));
        }
        return values;
    }

    /** Same canonical form as altcha-lib: JSON with recursively sorted object keys. */
    static String canonicalJson(JsonNode node) throws Exception {
        return JSON.writeValueAsString(canonicalValue(node));
    }

    private static Object canonicalValue(JsonNode node) {
        if (node == null || node.isNull()) {
            return null;
        }
        if (node.isObject()) {
            Map<String, Object> sorted = new TreeMap<>();
            node.properties().forEach(entry -> sorted.put(entry.getKey(), canonicalValue(entry.getValue())));
            return sorted;
        }
        if (node.isArray()) {
            List<Object> values = new ArrayList<>();
            node.forEach(value -> values.add(canonicalValue(value)));
            return values;
        }
        if (node.isTextual()) {
            return node.asText();
        }
        if (node.isBoolean()) {
            return node.asBoolean();
        }
        if (node.isIntegralNumber()) {
            return node.bigIntegerValue();
        }
        if (node.isFloatingPointNumber()) {
            // JavaScript has one number type, so 1.0 is signed as 1.
            BigDecimal value = node.decimalValue().stripTrailingZeros();
            return value.scale() <= 0 ? value.toBigIntegerExact() : value;
        }
        return node.asText();
    }

    private static boolean constantTimeEquals(String expected, String actual) {
        return MessageDigest.isEqual(
                expected.toLowerCase(Locale.ROOT).getBytes(StandardCharsets.US_ASCII),
                actual.toLowerCase(Locale.ROOT).getBytes(StandardCharsets.US_ASCII));
    }
}
