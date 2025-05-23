package org.nauthilus.keycloak;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.jboss.logging.Logger;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.models.UserModel;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class CustomAuthenticator extends UsernamePasswordForm {

    private static final Logger logger = Logger.getLogger(CustomAuthenticator.class);

    private static final String LOGIN_URL_ENV = "NAUTHILUS_LOGIN_URL";
    private static final String USERNAME_ENV = "NAUTHILUS_USERNAME";
    private static final String PASSWORD_ENV = "NAUTHILUS_PASSWORD";
    private static final String KEYCLOAK_PROTOCOL_ENV = "NAUTHILUS_PROTOCOL";

    private static final String DEFAULT_AUTH_SERVICE = "keycloak";

    @Override
    public void action(AuthenticationFlowContext context) {
        String username = context.getHttpRequest().getDecodedFormParameters().getFirst("username");
        String password = context.getHttpRequest().getDecodedFormParameters().getFirst("password");

        String userAgent = context.getHttpRequest().getHttpHeaders().getHeaderString("User-Agent");
        String sslState = context.getHttpRequest().getHttpHeaders().getHeaderString("X-SSL");
        String sslProtocol = context.getHttpRequest().getHttpHeaders().getHeaderString("X-SSL-Protocol");
        String sslCipher = context.getHttpRequest().getHttpHeaders().getHeaderString("X-SSL-Cipher");

        String oidcClientId = context.getAuthenticationSession().getClient().getClientId();

        logger.debug("Username: " + username);
        logger.debug("User-Agent: " + userAgent);
        logger.debug("SSL State: " + sslState);
        logger.debug("SSL Protocol: " + sslProtocol);
        logger.debug("SSL Cipher: " + sslCipher);
        logger.debug("OIDC Client ID: " + oidcClientId);

        String clientIP = context.getHttpRequest().getHttpHeaders().getHeaderString("X-Forwarded-For");
        if (clientIP == null) {
            clientIP = context.getConnection().getRemoteAddr();
        }

        int clientPort = context.getConnection().getRemotePort();

        try {
            boolean success = verifyNauthilusServer(
                    context, username, password, clientIP, clientPort, userAgent, sslState, sslProtocol, sslCipher, oidcClientId);

            if (success) {
                context.success();
            } else {
                context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
            }
        } catch (Exception e) {
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
        }
    }

    private boolean verifyNauthilusServer(AuthenticationFlowContext context, String username, String password, String clientIP, int clientPort, String userAgent, String sslState, String sslCipher, String sslProtocol, String oidcClientId) throws Exception {
        URL url = new URL(getApiUrl(context));
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();

        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");

        String baUsername = getUsername(context);
        String baPassword = getPassword(context);

        if (baUsername != null && baPassword != null) {
            String basicAuth = "Basic " + Base64.getEncoder().encodeToString((baUsername + ":" + baPassword).getBytes());
            conn.setRequestProperty("Authorization", basicAuth);
        }

        conn.setDoOutput(true);

        String effectiveSSLState = sslState != null ? sslState : "off";
        String effectiveSSLProtocol = sslProtocol != null ? sslProtocol : "";
        String effectiveSSLCipher = sslCipher != null ? sslCipher : "";
        String effectiveUserAgent = userAgent != null ? userAgent : "";
        String nauthilusProtocol = getNauthilusProtocol(context);

        Map<String, String> bodyMap = new HashMap<>();

        bodyMap.put("username", username);
        bodyMap.put("password", password);
        bodyMap.put("client_ip", clientIP);
        bodyMap.put("client_port", String.valueOf(clientPort));
        bodyMap.put("client_id", context.getRealm().getName());
        bodyMap.put("service", nauthilusProtocol == null ? DEFAULT_AUTH_SERVICE : nauthilusProtocol);
        bodyMap.put("ssl", effectiveSSLState);
        bodyMap.put("ssl_protocol", effectiveSSLProtocol);
        bodyMap.put("ssl_cipher", effectiveSSLCipher);
        bodyMap.put("user_agent", effectiveUserAgent);
        bodyMap.put("oidc_cid", oidcClientId);

        ObjectMapper objectMapper = new ObjectMapper();

        String body = objectMapper.writeValueAsString(bodyMap);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(body.getBytes());
            os.flush();
        }

        int responseCode = conn.getResponseCode();

        if (responseCode == 200) {
            String accountName = conn.getHeaderField("Auth-User");

            if (accountName == null || accountName.isEmpty()) {
                logger.warn("Auth-User header is missing or empty.");

                return false;
            }

            UserModel user = context.getSession().users().getUserByUsername(context.getRealm(), accountName);

            if (user == null) {
                logger.error("User not found in realm for accountName: " + accountName);
                context.failure(AuthenticationFlowError.INVALID_USER);

                return false;
            }

            context.setUser(user);

            return true;
        }

        return false;
    }

    private static String getConfigValue(AuthenticationFlowContext context, String key) {
        return context.getAuthenticatorConfig().getConfig().get(key);
    }

    private String getApiUrl(AuthenticationFlowContext context) {
        if (System.getenv(LOGIN_URL_ENV) != null) {
            return System.getenv(LOGIN_URL_ENV);
        }

        return getConfigValue(context, CustomAuthenticatorFactory.NAUTHILUS_LOGIN_URL);
    }

    private String getUsername(AuthenticationFlowContext context) {
        if (System.getenv(USERNAME_ENV) != null) {
            return System.getenv(USERNAME_ENV);
        }

        return getConfigValue(context, CustomAuthenticatorFactory.NAUTHILUS_USERNAME);
    }

    private String getPassword(AuthenticationFlowContext context) {
        if (System.getenv(PASSWORD_ENV) != null) {
            return System.getenv(PASSWORD_ENV);
        }

        return getConfigValue(context, CustomAuthenticatorFactory.NAUTHILUS_PASSWORD);
    }

    private String getNauthilusProtocol(AuthenticationFlowContext context) {
        if (System.getenv(KEYCLOAK_PROTOCOL_ENV) != null) {
            return System.getenv(KEYCLOAK_PROTOCOL_ENV);
        }

        return getConfigValue(context, CustomAuthenticatorFactory.NAUTHILUS_PROTOCOL);
    }

    @Override
    public boolean requiresUser() {
        return false;
    }
}
