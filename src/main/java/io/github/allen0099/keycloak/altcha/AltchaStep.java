package io.github.allen0099.keycloak.altcha;

import java.util.List;
import java.util.Map;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

/**
 * What the ALTCHA authenticators share: their admin-console settings, and issuing / checking a
 * challenge inside an authentication flow.
 *
 * <p>Settings are the execution's authenticator config, so they are edited from the gear icon on
 * the flow step in the admin console, or through the Admin REST API
 * ({@code /admin/realms/{realm}/authentication/config/{id}}). With no config saved, the defaults
 * apply and ALTCHA is on.
 */
final class AltchaStep {

    /** kcContext attribute the theme reads the challenge JSON from. */
    static final String ATTRIBUTE = "altchaChallenge";
    /** Message key shown when the check fails; bundled in theme-resources/messages. */
    static final String ERROR_MESSAGE = "altchaFailed";
    static final String EVENT_ERROR = "invalid_captcha";
    /**
     * Event detail set when a challenge is solved, so whatever event the request ends with (LOGIN,
     * LOGIN_ERROR, SEND_RESET_PASSWORD...) shows it got past the captcha. Absent when ALTCHA is off.
     */
    static final String EVENT_DETAIL = "altcha";
    static final String EVENT_DETAIL_PASSED = "passed";

    static final String ENABLED = "altchaEnabled";
    static final String DIFFICULTY = "altchaDifficulty";
    static final String COST = "altchaCost";
    static final String TTL = "altchaTtlSeconds";

    private static final String NOTE = "altcha.challenge";
    private static final long MAX_TTL = 3600;

    // Labels and help texts are message keys: the admin console looks them up in the "messages"
    // bundle, which includes this jar's theme-resources/messages. (Factory display type and help
    // text are not translated by the admin console, so those stay English literals.)
    static final List<ProviderConfigProperty> CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
            .property().name(ENABLED).type(ProviderConfigProperty.BOOLEAN_TYPE)
            .label("altchaEnabledLabel").helpText("altchaEnabledHelp")
            .defaultValue("true").add()
            .property().name(DIFFICULTY).type(ProviderConfigProperty.LIST_TYPE)
            .label("altchaDifficultyLabel").helpText("altchaDifficultyHelp")
            .options("3", "4")
            .defaultValue(Integer.toString(Altcha.Settings.DEFAULT.difficulty())).add()
            .property().name(COST).type(ProviderConfigProperty.INTEGER_TYPE)
            .label("altchaCostLabel").helpText("altchaCostHelp")
            .defaultValue(Altcha.Settings.DEFAULT.cost()).add()
            .property().name(TTL).type(ProviderConfigProperty.INTEGER_TYPE)
            .label("altchaTtlLabel").helpText("altchaTtlHelp")
            .defaultValue(Altcha.Settings.DEFAULT.ttlSeconds()).add()
            .build();

    private AltchaStep() {}

    static boolean enabled(AuthenticatorConfigModel config) {
        String v = values(config).get(ENABLED);
        return v == null || Boolean.parseBoolean(v);
    }

    /** Out-of-range or unparsable values fall back to the default rather than failing logins. */
    static Altcha.Settings settings(AuthenticatorConfigModel config) {
        Map<String, String> v = values(config);
        Altcha.Settings d = Altcha.Settings.DEFAULT;
        return new Altcha.Settings(
                (int) bounded(v.get(DIFFICULTY), 3, 4, d.difficulty()),
                (int) bounded(v.get(COST), 1, 1000, d.cost()),
                bounded(v.get(TTL), 60, MAX_TTL, d.ttlSeconds()));
    }

    /** Issue a fresh challenge for the page about to be rendered (no-op when disabled). */
    static void prepare(AuthenticationFlowContext context) {
        if (!enabled(context.getAuthenticatorConfig())) {
            context.getAuthenticationSession().removeAuthNote(NOTE);
            return;
        }
        Altcha.Issued issued = Altcha.issue(settings(context.getAuthenticatorConfig()), now());
        context.getAuthenticationSession().setAuthNote(NOTE, issued.record());
        context.form().setAttribute(ATTRIBUTE, issued.challengeJson());
    }

    /** Check the submitted payload. Consumes the challenge either way, so an answer works once. */
    static boolean passes(AuthenticationFlowContext context, String payload) {
        if (!enabled(context.getAuthenticatorConfig())) {
            return true;
        }
        String record = context.getAuthenticationSession().getAuthNote(NOTE);
        context.getAuthenticationSession().removeAuthNote(NOTE);
        // Removing the note only stops sequential reuse: parallel requests in one auth session all
        // read it before the removal is committed. The single-use store's putIfAbsent is atomic,
        // cluster-wide too, so only one of them gets through. The entry outlives any challenge.
        boolean passed = Altcha.verify(record, payload, now())
                && context.getSession().singleUseObjects().putIfAbsent(NOTE + ":" + record, MAX_TTL);
        if (passed) {
            // Only reaches events logged in this request; a login finished later (OTP,
            // required actions) carries no detail. Persist it as an auth note if those must count.
            context.getEvent().detail(EVENT_DETAIL, EVENT_DETAIL_PASSED);
        }
        return passed;
    }

    private static Map<String, String> values(AuthenticatorConfigModel config) {
        return config == null || config.getConfig() == null ? Map.of() : config.getConfig();
    }

    private static long bounded(String value, long min, long max, long fallback) {
        try {
            long n = Long.parseLong(value.trim());
            return n < min || n > max ? fallback : n;
        } catch (RuntimeException e) {
            return fallback;
        }
    }

    private static long now() {
        return System.currentTimeMillis() / 1000;
    }
}
