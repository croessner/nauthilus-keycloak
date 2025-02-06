package org.nauthilus.keycloak;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordFormFactory;
import org.keycloak.models.KeycloakSession;

public class CustomAuthenticatorFactory extends UsernamePasswordFormFactory {

    private static final String PROVIDER_ID = "nauthilus-authenticator";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Nauthilus Authenticator";
    }

    @Override
    public String getHelpText() {
        return "Collects username and password from a form and forwards the request to Nauthilus.";
    }

    @Override
    public String getReferenceCategory() {
        return "Nauthilus connector";
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new CustomAuthenticator();
    }
}
