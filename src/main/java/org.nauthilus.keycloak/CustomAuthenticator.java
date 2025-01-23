package org.nauthilus.keycloak;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.jboss.logging.Logger;
import jakarta.ws. rs.core.Response;
import org.keycloak.models.UserModel;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;

public class CustomAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(CustomAuthenticator.class);
    private static final String LOGIN_URL_ENV = "NAUTHILUS_LOGIN_URL";
    private static final String USERNAME_ENV = "NAUTHILUS_USERNAME";
    private static final String PASSWORD_ENV = "NAUTHILUS_PASSWORD";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        logger.debug("authenticate() called!");

        Response challenge = context.form()
                .setAttribute("username", "")
                .setAttribute("password", "")
                .setError("")
                .createLoginUsernamePassword();
        context.challenge(challenge);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        logger.debug("action() called!");

        String username = context.getHttpRequest().getDecodedFormParameters().getFirst("username");
        String password = context.getHttpRequest().getDecodedFormParameters().getFirst("password");
        String userAgent = context.getHttpRequest().getHttpHeaders().getHeaderString("User-Agent");

        logger.debug("Username: " + username);

        String clientIP = context.getHttpRequest().getHttpHeaders().getHeaderString("X-Forwarded-For");
        if (clientIP == null) {
            clientIP = context.getConnection().getRemoteAddr();
        }

        int clientPort = context.getConnection().getRemotePort();

        try {
            boolean success = verifyNauthilusServer(context, username, password, clientIP, clientPort, userAgent);

            if (success) {
                context.success();
            } else {
                context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
            }
        } catch (Exception e) {
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
        }
    }

    private boolean verifyNauthilusServer(AuthenticationFlowContext context, String username, String password, String clientIP, int clientPort, String userAgent) throws Exception {
        logger.debug("verifyNauthilusServer() called!");

        URL url = new URL(getApiUrl());
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");

        String baUsername = getUsername();
        String baPassword = getPassword();

        if (baUsername != null && baPassword != null) {
            String basicAuth = "Basic " + Base64.getEncoder().encodeToString((baUsername + ":" + baPassword).getBytes());
            conn.setRequestProperty("Authorization", basicAuth);
        }

        conn.setDoOutput(true);

        String body = String.format(
                "{\"username\":\"%s\",\"password\":\"%s\",\"client_ip\":\"%s\",\"client_port\":\"%d\",\"client_id\":\"%s\",\"service\":\"keycloak\",\"ssl\":\"on\"}",
                username, password, clientIP, clientPort, userAgent
        );

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

    private String getApiUrl() {
        return System.getenv(LOGIN_URL_ENV);
    }

    private String getUsername() {
        return System.getenv(USERNAME_ENV);
    }

    private String getPassword() {
        return System.getenv(PASSWORD_ENV);
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(org.keycloak.models.KeycloakSession session, org.keycloak.models.RealmModel realm, org.keycloak.models.UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(org.keycloak.models.KeycloakSession session, org.keycloak.models.RealmModel realm, org.keycloak.models.UserModel user) {
        // unused
    }

    @Override
    public void close() {
        // unused
    }
}

