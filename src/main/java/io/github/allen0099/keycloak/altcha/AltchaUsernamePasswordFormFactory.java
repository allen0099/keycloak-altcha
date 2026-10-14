package io.github.allen0099.keycloak.altcha;

import java.util.List;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordFormFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

public class AltchaUsernamePasswordFormFactory extends UsernamePasswordFormFactory {

    public static final String PROVIDER_ID = "altcha-username-password-form";

    @Override
    public Authenticator create(KeycloakSession session) {
        return new AltchaUsernamePasswordForm(session);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Username Password Form with ALTCHA";
    }

    @Override
    public String getHelpText() {
        return "The built-in username/password form, requiring a solved ALTCHA challenge before credentials are checked.";
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
