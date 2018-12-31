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

import static br.com.experimental.keycloak.authenticator.WebauthnLogin.U2fDecision.ABSTAIN;
import static br.com.experimental.keycloak.authenticator.WebauthnLogin.U2fDecision.SHOW_U2F;
import static br.com.experimental.keycloak.authenticator.WebauthnLogin.U2fDecision.SKIP_U2F;
import static br.com.experimental.keycloak.authenticator.WebauthnLoginFactory.*;
import static org.keycloak.models.utils.KeycloakModelUtils.getRoleFromString;

public class WebauthnLogin implements Authenticator {

    Logger logger = Logger.getLogger(this.getClass());

    private static final String atrib2f_fido_login = "2f_fido_login";

    private AuthenticationFlowContext context;
    private String clientId="";
    private AuthenticationFlowContext contexto;
    private KeycloakSession session;

    enum U2fDecision {
        SKIP_U2F, SHOW_U2F, ABSTAIN
    }

    public void authenticate(AuthenticationFlowContext context) {
        logger.info("Authenticate");

        this.contexto = context;
        this.session = context.getSession();
        Map<String, String> config = context.getAuthenticatorConfig().getConfig();

        if (context != null) {
            try {

                RealmModel realm = context.getRealm();
                UserModel user = context.getUser();

                //Set<String> lista = contexto.getSession().userCredentialManager().getDisableableCredentialTypes(contexto.getRealm(),contexto.getUser());
                boolean u2f = contexto.getSession().userCredentialManager().isConfiguredFor(realm, user, WebauthnCredentialProvider.TYPE);

                logger.info("authenticate - u2f: " + u2f);

                if (u2f) {
                    logger.info("authenticate - Contem U2F");

                    try {
                        clientId = context.getSession().getContext().getClient().getClientId();
                        logger.info("clientId: " + clientId);


                        if (config.containsKey(FORCE_U2F_FOR_CLIENT_EXCEPTION) && !config.get(FORCE_U2F_FOR_CLIENT_EXCEPTION).contains(clientId)) {
                            logger.info("authenticate - SHOW_U2F - NOT EXCEPTION");
                            showU2fForm(context);
                            return;
                        }

                    } catch (Exception e) {
                        if (e.getMessage()!=null)
                            logger.info("authenticate - erro: " + e.getMessage());

                        logger.info("authenticate - Erro ao obter clientId");
                        return;
                    }
                }
            }
            catch(Exception ex) {
                logger.info("authenticate - Erro: " + ex.getMessage());
                return;
            }
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

    private U2fDecision voteForClient(Map<String, String> config) {

        logger.info("voteForClient");

        try {
            clientId = this.session.getContext().getClient().getClientId();
            logger.info("clientId: " + clientId);
        } catch (Exception e) {
            if (e.getMessage()!=null)
                logger.info("voteForClient - erro: " + e.getMessage());

            logger.info("voteForClient - Erro ao obter clientId");
            return ABSTAIN;
        }

        if (clientId == null || clientId.equals("")) {
            logger.info("voteForClient - clientId vazio!");
            return ABSTAIN;
        }


        if (!config.containsKey(FORCE_U2F_FOR_CLIENT)) {
            return ABSTAIN;
        }

        if (config.containsKey(FORCE_U2F_FOR_CLIENT) && config.get(FORCE_U2F_FOR_CLIENT).contains("-" + clientId)) {
            return SKIP_U2F;
        }

        if (config.containsKey(FORCE_U2F_FOR_CLIENT) &&
                (config.get(FORCE_U2F_FOR_CLIENT).contains(clientId) || config.get(FORCE_U2F_FOR_CLIENT).contains("*"))) {
            if (!excecao(config.get(FORCE_U2F_FOR_CLIENT))) {
                return SHOW_U2F;
            }

        }


        return ABSTAIN;
    }

    private boolean excecao(String clientes) {
        logger.info("client: " + clientId + " " + clientes);
        if (!clientes.contains(clientId) || contexto==null) return false;
        logger.info("client: " + clientId + " " + clientes);

        String lista[] = clientes.split(",");

        for (String c: lista) {
            if (c.contains(clientId)) {
                int p = c.indexOf(":");
                if (p<0) return false;

                logger.info("IP: " + contexto.getSession().getContext().getConnection().getRemoteAddr());
                String ipConexao = contexto.getSession().getContext().getConnection().getRemoteAddr();


                String ips = c.substring(p+1);

                String listaIps[] = ips.split(";");
                logger.info("lista: " + listaIps);

                listaIps = ips.split("\\|");
                logger.info("lista: " + listaIps);

                for (String ip: listaIps) {
                    logger.info("comp: " + ip + "=" + ipConexao.substring(0,ip.length()));
                    if (ip.equals(ipConexao.substring(0,ip.length()))) {
                        logger.info("achou");
                        return true;
                    }
                }

            }
        }
        return false;
    }

    private U2fDecision voteForUserU2fControlAttribute(UserModel user, Map<String, String> config) {

        if (!config.containsKey(U2F_CONTROL_USER_ATTRIBUTE)) {
            return ABSTAIN;
        }

        String attributeName = config.get(U2F_CONTROL_USER_ATTRIBUTE);
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
                return SKIP_U2F;
            case FORCE:
                return SHOW_U2F;
            default:
                return ABSTAIN;
        }
    }

    private U2fDecision voteForUserRole(RealmModel realm, UserModel user, Map<String, String> config) {

        if (!config.containsKey(FORCE_U2F_ROLE)) {
            return ABSTAIN;
        }

        String[] lista = config.get(FORCE_U2F_ROLE).split(",");

        for (String s: lista) {
            if (s.substring(0,1).equals("-")) {
                if (userHasRole(realm, user, s.substring(1))) {
                    return SKIP_U2F;
                }
            }
        }

        for (String s: lista) {
            if (s.equals("*") || userHasRole(realm, user, s)) {
                return SHOW_U2F;
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

    private U2fDecision voteForHttpHeaderMatchesPattern(MultivaluedMap<String, String> requestHeaders, Map<String, String> config) {

        if (!config.containsKey(FORCE_U2F_FOR_HTTP_HEADER) && !config.containsKey(SKIP_U2F_FOR_HTTP_HEADER)) {
            return ABSTAIN;
        }

        //Inverted to allow white-lists, e.g. for specifying trusted remote hosts: X-Forwarded-Host: (1.2.3.4|1.2.3.5)
        if (containsMatchingRequestHeader(requestHeaders, config.get(SKIP_U2F_FOR_HTTP_HEADER))) {
            return SKIP_U2F;
        }

        if (containsMatchingRequestHeader(requestHeaders, config.get(FORCE_U2F_FOR_HTTP_HEADER))) {
            return SHOW_U2F;
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

    private U2fDecision voteForDefaultFallback(Map<String, String> config) {

        if (!config.containsKey(DEFAULT_U2F_OUTCOME)) {
            return ABSTAIN;
        }

        switch (config.get(DEFAULT_U2F_OUTCOME)) {
            case SKIP:
                return SKIP_U2F;
            case FORCE:
                return SHOW_U2F;
            default:
                return ABSTAIN;
        }
    }

    private boolean tryConcludeBasedOn(U2fDecision state, AuthenticationFlowContext context) {

        switch (state) {

            case SHOW_U2F:
                showU2fForm(context);
                return true;

            case SKIP_U2F:
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
                    .createForm("fido-webauthn-login.ftl");

            context.challenge(response);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private boolean isRequiredU2f(KeycloakSession session, RealmModel realm, UserModel user) {

        logger.info("isU2fRequired");
        MultivaluedMap<String, String> requestHeaders = session.getContext().getRequestHeaders().getRequestHeaders();

        AuthenticatorConfigModel configModel = getConfigU2f(session, PROVIDER_ID);

        logger.info("configModel: " + configModel);

        if (configModel==null) {
            return false;
        }

        this.session = session;

        U2fDecision state = ABSTAIN;

        state = voteForClient(configModel.getConfig());

        logger.info("state: " + state);
        if (state == SKIP_U2F) {
            return false;
        } else if (state == SHOW_U2F) {
            return true;
        }

        state = voteForUserU2fControlAttribute(user, configModel.getConfig());
        if (state == SKIP_U2F) {
            return false;
        } else if (state == SHOW_U2F) {
            return true;
        }

        state = voteForUserRole(realm, user, configModel.getConfig());
        if (state == SKIP_U2F) {
            return false;
        } else if (state == SHOW_U2F) {
            return true;
        }

        state = voteForHttpHeaderMatchesPattern(requestHeaders, configModel.getConfig());
        if (state == SKIP_U2F) {
            return false;
        } else if (state == SHOW_U2F) {
            return true;
        }

        if (configModel.getConfig().get(DEFAULT_U2F_OUTCOME) != null
                && configModel.getConfig().get(DEFAULT_U2F_OUTCOME).equals(FORCE)) {
            return true;
        }

        return false;
    }

    AuthenticatorConfigModel getConfigU2f(KeycloakSession session, String providerId) {
        logger.info("getConfig: " + session + " " + providerId);

        AuthenticatorConfigModel configModel = null;
        RealmModel realm = session.getContext().getRealm();

        String flowId = realm.getBrowserFlow().getId();

        List<AuthenticationExecutionModel> laem = realm.getAuthenticationExecutions(flowId);

        for (AuthenticationExecutionModel aem : laem) {

            if (aem.getAuthenticator() != null) {
                logger.info("getConfigU2f: ID: " + aem.getId() + " Nome: " + aem.getAuthenticator());
            }

            if (aem.getAuthenticator() != null && aem.getAuthenticator().equals(providerId)) {

                configModel = realm.getAuthenticatorConfigById(aem.getAuthenticatorConfig());
                logger.info("achou config: " + configModel);
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

            CredentialModel savedCredential = Server.finishAssertion(context, data, session);

            String handle = savedCredential.getId();

            logger.info("handle: " + handle);

            context.getClientSession().setUserSessionNote(atrib2f_fido_login, "true");

            context.success();
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
        /*
        if (!user.getRequiredActions().contains(WebauthnRequiredActionProviderFactory.ID)) {
            user.addRequiredAction(WebauthnRequiredActionProviderFactory.ID);
        }
        */

        logger.info("setRequired");
        if (!isRequiredU2f(session, realm, user)) {
            //logger.info("remove");
            user.removeRequiredAction(WebauthnRequiredActionProviderFactory.ID);
        } else if (!user.getRequiredActions().contains(WebauthnRequiredActionProviderFactory.ID)) {
            user.addRequiredAction(WebauthnRequiredActionProviderFactory.ID);
        }

    }


    public void close() {
        // Não utilizado
    }

}
