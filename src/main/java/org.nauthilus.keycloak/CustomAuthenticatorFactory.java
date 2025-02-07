package org.nauthilus.keycloak;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordFormFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;
import java.util.ArrayList;

import static org.keycloak.provider.ProviderConfigProperty.STRING_TYPE;

public class CustomAuthenticatorFactory extends UsernamePasswordFormFactory {

    private static final String PROVIDER_ID = "nauthilus-authenticator";

    static final String NAUTHILUS_LOGIN_URL = "nauthilus_login_url";
    static final String NAUTHILUS_USERNAME = "nauthilus_username";
    static final String NAUTHILUS_PASSWORD = "nauthilus_password";
    static final String NAUTHILUS_PROTOCOL = "nauthilus_protocol";

    @Override
    public boolean isConfigurable() {
        return true;
    }

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

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        List<ProviderConfigProperty> configProperties = new ArrayList<>();

        ProviderConfigProperty loginUrl = new ProviderConfigProperty();
        loginUrl.setType(STRING_TYPE);
        loginUrl.setName(NAUTHILUS_LOGIN_URL);
        loginUrl.setLabel("Nauthilus login URL");
        loginUrl.setHelpText("This is the URL of the Nauthilus instance including the /api/v1/auth/json path.");
        configProperties.add(loginUrl);

        ProviderConfigProperty username = new ProviderConfigProperty();
        username.setType(STRING_TYPE);
        username.setName(NAUTHILUS_USERNAME);
        username.setLabel("Nauthilus username");
        username.setHelpText("The optional username for authenticating with the Nauthilus instance.");
        configProperties.add(username);

        ProviderConfigProperty password = new ProviderConfigProperty();
        password.setType(STRING_TYPE);
        password.setName(NAUTHILUS_PASSWORD);
        password.setLabel("Nauthilus password");
        password.setHelpText("The optional password for authenticating with the Nauthilus instance.");
        configProperties.add(password);

        ProviderConfigProperty keycloakProtocol = new ProviderConfigProperty();
        keycloakProtocol.setType(STRING_TYPE);
        keycloakProtocol.setName(NAUTHILUS_PROTOCOL);
        keycloakProtocol.setLabel("Nauthilus protocol");
        keycloakProtocol.setHelpText("Nauthilus protocol name for this instance, i.e. keycloak.");
        configProperties.add(keycloakProtocol);

        return configProperties;
    }
}
