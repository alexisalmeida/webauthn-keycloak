package br.com.experimental.keycloak.authenticator;

import com.google.gson.JsonObject;
import com.google.webauthn.gaedemo.server.Server;
import org.jboss.logging.Logger;
import org.keycloak.authentication.*;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.*;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.*;
import java.util.regex.Pattern;

import org.keycloak.models.utils.RoleUtils;

import static br.com.experimental.keycloak.authenticator.WebauthnLogin.WebauthnDecision.ABSTAIN;
import static br.com.experimental.keycloak.authenticator.WebauthnLogin.WebauthnDecision.SHOW_WAUTHN;
import static br.com.experimental.keycloak.authenticator.WebauthnLogin.WebauthnDecision.SKIP_WAUTHN;
import static br.com.experimental.keycloak.authenticator.WebauthnLoginFactory.*;
import static org.keycloak.models.utils.KeycloakModelUtils.getRoleFromString;

public class WebauthnLogin implements Authenticator {

    private Logger logger = Logger.getLogger(this.getClass());

    private static final String atrib_webauthn_login = "webauthn_login";

    private AuthenticationFlowContext context;
    private String clientId="";
    private AuthenticationFlowContext contexto;
    private KeycloakSession session;

    enum WebauthnDecision {
        SKIP_WAUTHN, SHOW_WAUTHN, ABSTAIN
    }

    public void authenticate(AuthenticationFlowContext context) {
        this.contexto = context;
        this.session = context.getSession();

        Map<String, String> config = context.getAuthenticatorConfig().getConfig();

        try {

            RealmModel realm = context.getRealm();
            UserModel user = context.getUser();

            boolean webauthn = contexto.getSession().userCredentialManager().isConfiguredFor(realm, user, WebauthnCredentialProvider.TYPE);

            if (webauthn) {
                logger.info("Authenticate - User has Webauthn");

                try {
                    clientId = context.getSession().getContext().getClient().getClientId();
                    logger.info("clientId: " + clientId);


                    if (config.containsKey(FORCE_WAUTHN_FOR_CLIENT_EXCEPTION) && !config.get(FORCE_WAUTHN_FOR_CLIENT_EXCEPTION).contains(clientId)) {
                        logger.info("Authenticate - SHOW_WAUTHN - NOT EXCEPTION");
                        showU2fForm(context);
                        return;
                    }

                } catch (Exception e) {
                    if (e.getMessage()!=null)
                        logger.info("Authenticate - error: " + e.getMessage());

                    logger.info("Authenticate - Error getting clientId");
                    return;
                }
            }
        }
        catch(Exception ex) {
            logger.info("Authenticate - Error: " + ex.getMessage());
            return;
        }

        if (tryConcludeBasedOn(voteForClient(config), context)) {
            return;
        }

        if (tryConcludeBasedOn(voteForUserU2fControlAttribute(context.getUser(), config), context)) {
            return;
        }

        if (tryConcludeBasedOn(voteForUserRole(context.getRealm(), context.getUser(), config), context)) {
            return;
        }

        if (tryConcludeBasedOn(voteForHttpHeaderMatchesPattern(context.getHttpRequest().getHttpHeaders().getRequestHeaders(), config), context)) {
            return;
        }

        if (tryConcludeBasedOn(voteForDefaultFallback(config), context)) {
            return;
        }

        showU2fForm(context);


    }

    private WebauthnDecision voteForClient(Map<String, String> config) {

        logger.info("voteForClient");

        try {
            clientId = this.session.getContext().getClient().getClientId();
        } catch (Exception e) {
            if (e.getMessage()!=null)
                logger.info("voteForClient - error: " + e.getMessage());

            logger.info("voteForClient - Error getting clientId");
            return ABSTAIN;
        }

        if (clientId == null || clientId.equals("")) {
            logger.info("voteForClient - clientId empty!");
            return ABSTAIN;
        }


        if (!config.containsKey(FORCE_WAUTHN_FOR_CLIENT)) {
            return ABSTAIN;
        }

        if (config.containsKey(FORCE_WAUTHN_FOR_CLIENT) && config.get(FORCE_WAUTHN_FOR_CLIENT).contains("-" + clientId)) {
            return SKIP_WAUTHN;
        }

        if (config.containsKey(FORCE_WAUTHN_FOR_CLIENT) &&
                (config.get(FORCE_WAUTHN_FOR_CLIENT).contains(clientId) || config.get(FORCE_WAUTHN_FOR_CLIENT).contains("*"))) {
            if (!excecao(config.get(FORCE_WAUTHN_FOR_CLIENT))) {
                return SHOW_WAUTHN;
            }
        }

        return ABSTAIN;
    }

    private boolean excecao(String clientes) {
        if (!clientes.contains(clientId) || contexto==null) return false;

        String lista[] = clientes.split(",");

        for (String c: lista) {
            if (c.contains(clientId)) {
                int p = c.indexOf(":");
                if (p<0) return false;

                String ipConexao = contexto.getSession().getContext().getConnection().getRemoteAddr();

                String ips = c.substring(p+1);
                String listaIps[] = ips.split("\\|");

                for (String ip: listaIps) {
                    if (ip.equals(ipConexao.substring(0,ip.length()))) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private WebauthnDecision voteForUserU2fControlAttribute(UserModel user, Map<String, String> config) {

        if (!config.containsKey(WAUTHN_CONTROL_USER_ATTRIBUTE)) {
            return ABSTAIN;
        }

        String attributeName = config.get(WAUTHN_CONTROL_USER_ATTRIBUTE);
        if (attributeName == null) {
            return ABSTAIN;
        }

        List<String> values = user.getAttribute(attributeName);

        if (values.isEmpty()) {
            return ABSTAIN;
        }

        String value = values.get(0).trim();

        switch (value) {
            case SKIP:
                return SKIP_WAUTHN;
            case FORCE:
                return SHOW_WAUTHN;
            default:
                return ABSTAIN;
        }
    }

    private WebauthnDecision voteForUserRole(RealmModel realm, UserModel user, Map<String, String> config) {

        if (!config.containsKey(FORCE_WAUTHN_ROLE)) {
            return ABSTAIN;
        }

        String[] lista = config.get(FORCE_WAUTHN_ROLE).split(",");

        for (String s: lista) {
            if (s.substring(0,1).equals("-")) {
                if (userHasRole(realm, user, s.substring(1))) {
                    return SKIP_WAUTHN;
                }
            }
        }

        for (String s: lista) {
            if (s.equals("*") || userHasRole(realm, user, s)) {
                return SHOW_WAUTHN;
            }
        }

        return ABSTAIN;
    }

    private boolean userHasRole(RealmModel realm, UserModel user, String roleName) {

        if (roleName == null) {
            return false;
        }

        RoleModel role = getRoleFromString(realm, roleName);

        return RoleUtils.hasRole(user.getRoleMappings(), role);
    }

    private WebauthnDecision voteForHttpHeaderMatchesPattern(MultivaluedMap<String, String> requestHeaders, Map<String, String> config) {

        if (!config.containsKey(FORCE_WAUTHN_FOR_HTTP_HEADER) && !config.containsKey(SKIP_WAUTHN_FOR_HTTP_HEADER)) {
            return ABSTAIN;
        }

        //Inverted to allow white-lists, e.g. for specifying trusted remote hosts: X-Forwarded-Host: (1.2.3.4|1.2.3.5)
        if (containsMatchingRequestHeader(requestHeaders, config.get(SKIP_WAUTHN_FOR_HTTP_HEADER))) {
            return SKIP_WAUTHN;
        }

        if (containsMatchingRequestHeader(requestHeaders, config.get(FORCE_WAUTHN_FOR_HTTP_HEADER))) {
            return SHOW_WAUTHN;
        }

        return ABSTAIN;
    }

    private boolean containsMatchingRequestHeader(MultivaluedMap<String, String> requestHeaders, String headerPattern) {

        if (headerPattern == null) {
            return false;
        }

        //TODO cache RequestHeader Patterns
        //TODO how to deal with pattern syntax exceptions?
        Pattern pattern = Pattern.compile(headerPattern, Pattern.DOTALL);

        for (Map.Entry<String, List<String>> entry : requestHeaders.entrySet()) {

            String key = entry.getKey();

            for (String value : entry.getValue()) {

                String headerEntry = key.trim() + ": " + value.trim();

                if (pattern.matcher(headerEntry).matches()) {
                    return true;
                }
            }
        }

        return false;
    }

    private WebauthnDecision voteForDefaultFallback(Map<String, String> config) {

        if (!config.containsKey(DEFAULT_WAUTHN_OUTCOME)) {
            return ABSTAIN;
        }

        switch (config.get(DEFAULT_WAUTHN_OUTCOME)) {
            case SKIP:
                return SKIP_WAUTHN;
            case FORCE:
                return SHOW_WAUTHN;
            default:
                return ABSTAIN;
        }
    }

    private boolean tryConcludeBasedOn(WebauthnDecision state, AuthenticationFlowContext context) {

        switch (state) {

            case SHOW_WAUTHN:
                showU2fForm(context);
                return true;

            case SKIP_WAUTHN:
                context.success();
                return true;

            default:
                return false;
        }
    }

    private void showU2fForm(AuthenticationFlowContext context) {

        try {

            JsonObject assertionJson = Server.startAssertion(context);

            Response response = context.form()
                    .setAttribute("request", assertionJson.toString())
                    .createForm("login-webauthn.ftl");

            context.challenge(response);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private boolean isRequiredU2f(KeycloakSession session, RealmModel realm, UserModel user) {

        MultivaluedMap<String, String> requestHeaders = session.getContext().getRequestHeaders().getRequestHeaders();
        AuthenticatorConfigModel configModel = getConfigU2f(session, PROVIDER_ID);

        if (configModel==null) {
            return false;
        }

        this.session = session;

        WebauthnDecision state;

        state = voteForClient(configModel.getConfig());

        logger.info("state: " + state);
        if (state == SKIP_WAUTHN) {
            return false;
        } else if (state == SHOW_WAUTHN) {
            return true;
        }

        state = voteForUserU2fControlAttribute(user, configModel.getConfig());
        if (state == SKIP_WAUTHN) {
            return false;
        } else if (state == SHOW_WAUTHN) {
            return true;
        }

        state = voteForUserRole(realm, user, configModel.getConfig());
        if (state == SKIP_WAUTHN) {
            return false;
        } else if (state == SHOW_WAUTHN) {
            return true;
        }

        state = voteForHttpHeaderMatchesPattern(requestHeaders, configModel.getConfig());
        if (state == SKIP_WAUTHN) {
            return false;
        } else if (state == SHOW_WAUTHN) {
            return true;
        }

        return configModel.getConfig().get(DEFAULT_WAUTHN_OUTCOME) != null
                && configModel.getConfig().get(DEFAULT_WAUTHN_OUTCOME).equals(FORCE);

    }

    private AuthenticatorConfigModel getConfigU2f(KeycloakSession session, String providerId) {
        AuthenticatorConfigModel configModel = null;

        RealmModel realm = session.getContext().getRealm();
        String flowId = realm.getBrowserFlow().getId();
        List<AuthenticationExecutionModel> laem = realm.getAuthenticationExecutions(flowId);

        for (AuthenticationExecutionModel aem : laem) {
            if (aem.getAuthenticator() != null && aem.getAuthenticator().equals(providerId)) {
                configModel = realm.getAuthenticatorConfigById(aem.getAuthenticatorConfig());
                break;
            }
        }

        return configModel;
    }



    public void action(AuthenticationFlowContext context) {
        try {
            MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

            String data = formData.getFirst("data");
            String session = formData.getFirst("session");

            if (data.equalsIgnoreCase("new-register")) {
                 context.getUser().addRequiredAction(WebauthnRequiredActionProviderFactory.ID);

                 context.success();
            } else {
                CredentialModel savedCredential = Server.finishAssertion(context, data, session);
                context.getAuthenticationSession().setUserSessionNote(atrib_webauthn_login, "true");

                context.success();
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public boolean requiresUser() {
        //TODO Para testes somente, se requerer um usuário autenticado deve retornar true
        return true;
    }


    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {

        return session.userCredentialManager().isConfiguredFor(realm, user, WebauthnCredentialProvider.TYPE);
    }


    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        if (!isRequiredU2f(session, realm, user)) {
            user.removeRequiredAction(WebauthnRequiredActionProviderFactory.ID);
        } else if (!user.getRequiredActions().contains(WebauthnRequiredActionProviderFactory.ID)) {
            user.addRequiredAction(WebauthnRequiredActionProviderFactory.ID);
        }
    }

    public void close() {
        // Not used
    }
}
