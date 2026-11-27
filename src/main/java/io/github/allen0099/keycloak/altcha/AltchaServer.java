package io.github.allen0099.keycloak.altcha;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.math.BigDecimal;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Duration;
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
    private static final Pattern EXPIRES_PARAMETER = Pattern.compile("[?&]expires=(\\d+)", Pattern.CASE_INSENSITIVE);
    private static final long MAX_COUNTER = 0xFFFFFFFFL;
    private static final Duration FETCH_TIMEOUT = Duration.ofSeconds(10);
    private static final int FETCH_ATTEMPTS = 3;
    private static final long FETCH_RETRY_DELAY_MS = 400L;
    private static final HttpClient HTTP = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    private AltchaServer() {}

    /**
     * Fetches the challenge of the external server, so that the browser does not have to.
     *
     * <p>The widget can fetch the challenge itself (it is given the URL), but then the browser
     * needs a working route to the server and the server has to allow the origin of the login
     * page.  Fetching the challenge here keeps that out of the browser: the challenge JSON goes
     * into the page, the widget only solves it.
     *
     * <p>The server can hiccup (a timeout, a connection that is refused, an answer that is not
     * JSON).  A single failed attempt would push the browser into the fallback -- the widget
     * fetching the challenge itself -- and that route does not work for every network, so the
     * request is repeated a few times before the fallback is used.
     *
     * @return the body of the answer (the challenge as JSON), or null when the server cannot be
     *     reached or does not answer with a JSON object
     */
    static String fetchChallenge(String url) {
        if (url == null || url.isBlank()) {
            return null;
        }
        for (int attempt = 1; attempt <= FETCH_ATTEMPTS; attempt++) {
            String challenge = fetchChallengeOnce(url);
            if (challenge != null) {
                return challenge;
            }
            if (attempt < FETCH_ATTEMPTS) {
                try {
                    Thread.sleep(FETCH_RETRY_DELAY_MS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return null;
                }
            }
        }
        return null;
    }

    private static String fetchChallengeOnce(String url) {
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                    .timeout(FETCH_TIMEOUT)
                    .header("Accept", "application/json")
                    .GET()
                    .build();
            HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                return null;
            }
            String body = response.body();
            if (body == null || body.isBlank()) {
                return null;
            }
            JsonNode root = JSON.readTree(body);
            return root != null && root.isObject() ? body : null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Returns the challenge URL the widget should fetch. When {@code apiKey} is set and the URL
     * does not carry one already, it is appended as the {@code apiKey} query parameter.
     */
    static String challengeUrl(String serverUrl, String apiKey) {
        return withApiKey(serverUrl, apiKey);
    }

    /**
     * Returns the URL the verification is reported to. The API key is appended like in the
     * challenge URL.
     */
    static String verifyUrl(String serverUrl, String apiKey) {
        return withApiKey(serverUrl, apiKey);
    }

    private static String withApiKey(String serverUrl, String apiKey) {
        String url = serverUrl == null ? "" : serverUrl.trim();
        if (apiKey == null || apiKey.isBlank() || API_KEY_PARAMETER.matcher(url).find()) {
            return url;
        }
        String separator = !url.contains("?") ? "?" : url.endsWith("?") || url.endsWith("&") ? "" : "&";
        return url + separator + "apiKey=" + URLEncoder.encode(apiKey.trim(), StandardCharsets.UTF_8);
    }

    /**
     * Reports a solved payload to the verification endpoint of the external server, so that the
     * server knows about the verification: it keeps its own statistics, and it can refuse
     * payloads it does not like (a replay, a bot score above its threshold).
     *
     * <p>The payload is sent as it was submitted, base64 encoded, in the field {@code payload} --
     * the shape the endpoints of the ALTCHA servers expect.
     *
     * @return {@code TRUE} when the server accepted the payload, {@code FALSE} when it refused it,
     *     {@code null} when it could not be reached at all
     */
    static Boolean forwardVerification(String url, String payload) {
        if (url == null || url.isBlank() || payload == null || payload.isBlank()) {
            return null;
        }
        try {
            String body = JSON.writeValueAsString(Map.of("payload", payload));
            HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                    .timeout(FETCH_TIMEOUT)
                    .header("Accept", "application/json")
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
            HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                return null;
            }
            JsonNode root = JSON.readTree(response.body());
            return root != null && root.path("ok").asBoolean(false);
        } catch (Exception e) {
            return null;
        }
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
            if (root.path("challenge").isTextual()
                    && root.hasNonNull("number")
                    && root.hasNonNull("salt")
                    && root.hasNonNull("signature")) {
                return verifyLegacy(root, secret, nowSeconds);
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
            if (root.path("challenge").isTextual() && root.hasNonNull("number") && root.hasNonNull("salt")) {
                // The older format: the signature belongs to the challenge, so it identifies it.
                return "legacy:" + signature;
            }
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

    /**
     * A payload of the older ALTCHA format, as the widget builds it for a challenge of the older
     * format: a flat object with the challenge, the number that solves it and the signature of
     * the challenge.
     *
     * <p>The proof of work is re-derived here: the challenge is the SHA-256 digest of the salt
     * and the number, and the signature is the HMAC of the challenge with the secret. The expiry
     * travels in the salt ({@code ?expires=...}) and is checked as well.
     */
    private static boolean verifyLegacy(JsonNode root, String secret, long nowSeconds)
            throws GeneralSecurityException {
        String algorithm = root.path("algorithm").asText("");
        if (!"SHA-256".equals(algorithm)) {
            return false;
        }
        String salt = root.path("salt").asText("");
        String challenge = root.path("challenge").asText("");
        String signature = root.path("signature").asText("");
        JsonNode number = root.path("number");
        if (salt.isEmpty() || challenge.isEmpty() || signature.isEmpty()
                || !(number.isNumber() || number.isTextual())) {
            return false;
        }
        Long expiresAt = expiresAt(salt);
        if (expiresAt != null && nowSeconds > expiresAt) {
            return false;
        }
        if (!constantTimeEquals(hmacHex(algorithm, challenge.getBytes(StandardCharsets.UTF_8), secret),
                signature)) {
            return false;
        }
        String key = sha256Hex((salt + number.asText()).getBytes(StandardCharsets.UTF_8));
        return constantTimeEquals(key, challenge);
    }

    /** The expiry of a challenge of the older format, if its salt carries one. */
    private static Long expiresAt(String salt) {
        var matcher = EXPIRES_PARAMETER.matcher(salt);
        if (!matcher.find()) {
            return null;
        }
        try {
            return Long.parseLong(matcher.group(1));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static String sha256Hex(byte[] data) throws GeneralSecurityException {
        return HEX.formatHex(MessageDigest.getInstance("SHA-256").digest(data));
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
