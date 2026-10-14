package io.github.allen0099.keycloak.altcha;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.List;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.authenticators.resetcred.ResetCredentialChooseUser;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;

/** The built-in forgot-password "choose user" step, plus a solved ALTCHA challenge before mail is sent. */
public class AltchaResetCredentialChooseUser extends ResetCredentialChooseUser {

    public static final String PROVIDER_ID = "altcha-reset-credential-choose-user";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        // harmless when super skips the form (SSO session, action token): nothing renders it
        AltchaStep.prepare(context);
        super.authenticate(context);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        boolean solved = AltchaStep.passes(context, formData.getFirst(Altcha.FORM_FIELD));
        // a fresh challenge for any page rendered from here on: the failure below or super's own errors
        AltchaStep.prepare(context);
        if (!solved) {
            context.getEvent().error(AltchaStep.EVENT_ERROR);
            String username = formData.getFirst("username");
            if (username != null) {
                // the reset page refills the field from this note, not from the form data
                context.getAuthenticationSession()
                        .setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, username.trim());
            }
            Response challenge = context.form()
                    .addError(new FormMessage(null, AltchaStep.ERROR_MESSAGE))
                    .createPasswordReset();
            // challenge, not failureChallenge: that would charge a brute-force failure to whoever
            // the note above names, for free
            context.challenge(challenge);
            return;
        }
        super.action(context);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Choose User with ALTCHA";
    }

    @Override
    public String getHelpText() {
        return "The built-in forgot-password \"Choose User\" step, requiring a solved ALTCHA challenge before any email is sent.";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return AltchaStep.CONFIG_PROPERTIES;
    }
}
