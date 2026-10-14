package io.github.allen0099.keycloak.altcha;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.keycloak.WebAuthnConstants;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.models.KeycloakSession;

/** The built-in username/password form, plus a solved ALTCHA challenge before credentials are checked. */
public class AltchaUsernamePasswordForm extends UsernamePasswordForm {

    public AltchaUsernamePasswordForm(KeycloakSession session) {
        super(session);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (isPasskeySubmission(formData)) {
            // super hands this to the passkey authenticator, which checks no password, so there is
            // nothing to protect. Its error page skips challenge(...), hence the explicit prepare.
            AltchaStep.prepare(context);
            super.action(context);
            return;
        }
        if (!formData.containsKey("cancel") && !AltchaStep.passes(context, formData.getFirst(Altcha.FORM_FIELD))) {
            context.getEvent().error(AltchaStep.EVENT_ERROR);
            context.form().setFormData(formData);
            // challenge, not failureChallenge: that would charge a brute-force failure to the
            // session's user or attempted username without the captcha having been solved
            context.challenge(challenge(context, AltchaStep.ERROR_MESSAGE, null));
            return;
        }
        super.action(context);
    }

    /** Same test as super's action uses to route a post to the passkey (conditional WebAuthn) authenticator. */
    private boolean isPasskeySubmission(MultivaluedMap<String, String> formData) {
        return webauthnAuth != null && webauthnAuth.isPasskeysEnabled()
                && (formData.containsKey(WebAuthnConstants.AUTHENTICATOR_DATA) || formData.containsKey(WebAuthnConstants.ERROR));
    }

    // Every page super renders goes through one of these two. context.form() is cached per
    // request, so the attribute set here reaches whichever page super builds.
    @Override
    protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        AltchaStep.prepare(context);
        return super.challenge(context, formData);
    }

    @Override
    protected Response challenge(AuthenticationFlowContext context, String error, String field) {
        AltchaStep.prepare(context);
        return super.challenge(context, error, field);
    }
}
