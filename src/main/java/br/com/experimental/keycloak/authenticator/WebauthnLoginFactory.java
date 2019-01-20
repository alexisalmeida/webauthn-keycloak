package br.com.experimental.keycloak.authenticator;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import java.util.ArrayList;
import java.util.List;

import static java.util.Arrays.asList;
import static org.keycloak.provider.ProviderConfigProperty.LIST_TYPE;
import static org.keycloak.provider.ProviderConfigProperty.STRING_TYPE;

public class WebauthnLoginFactory implements AuthenticatorFactory {

    private Logger logger = Logger.getLogger(this.getClass());

    static final String PROVIDER_ID = "webauthn-login";
    private final WebauthnLogin SINGLETON = new WebauthnLogin();

    static final String SKIP = "skip";
    static final String FORCE = "force";
    static final String WAUTHN_CONTROL_USER_ATTRIBUTE = "u2fControlAttribute";
    static final String FORCE_WAUTHN_ROLE = "forceU2fRole";
    static final String SKIP_WAUTHN_FOR_HTTP_HEADER = "noU2fRequiredForHeaderPattern";
    static final String FORCE_WAUTHN_FOR_HTTP_HEADER = "forceU2fForHeaderPattern";
    static final String DEFAULT_WAUTHN_OUTCOME = "defaultU2fOutcome";
    static final String FORCE_WAUTHN_FOR_CLIENT = "forceU2fForClient";
    static final String FORCE_WAUTHN_FOR_CLIENT_EXCEPTION = "forceU2fClientException";


    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();
    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.OPTIONAL,
            AuthenticationExecutionModel.Requirement.DISABLED};

    static {
        String msg = "Lista de clientes para os quais será solicitado o U2F";

        ProviderConfigProperty property;

        property = new ProviderConfigProperty();
        property.setType(STRING_TYPE);
        property.setName(FORCE_WAUTHN_FOR_CLIENT);
        property.setLabel("Reaquire Webauthn for clients");
        property.setHelpText("Webauthn will be required for clients in the list (comma separated). " +
                "Use * for all clients. " +
                "If you want to omit a specific client, please enter it preceded by a \"-\" ");
        property.setDefaultValue("");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setType(STRING_TYPE);
        property.setName(FORCE_WAUTHN_FOR_CLIENT_EXCEPTION);
        property.setLabel("U2F exceção para clientes");
        property.setHelpText("O U2F não será exigido para os clientes da lista (separado por vírgula).");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setType(STRING_TYPE);
        property.setName(WAUTHN_CONTROL_USER_ATTRIBUTE);
        property.setLabel("Atributo do Usuário");
        property.setHelpText("O nome do atributo que controla o uso do U2F. " +
                "Se o valor do atributo é 'force', então o U2F é exigido. " +
                "Se o valor é 'skip', o U2F é ignorado. Para outros valores essa verificação é ignorada.");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setType(STRING_TYPE);
        property.setName(FORCE_WAUTHN_ROLE);
        property.setLabel("U2F para as Roles");
        property.setHelpText("O U2F será exigido para as Roles listadas. Use * para todas as Roles." +
                "Caso deseje excluir uma role, prefixe-a com -.");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setType(STRING_TYPE);
        property.setName(SKIP_WAUTHN_FOR_HTTP_HEADER);
        property.setLabel("Dispensa U2F pelo Header");
        property.setHelpText("O U2F é dispensado se um header do request HTTP atende um determinado padrão." +
                "Pode ser usado para especificar redes confiáveis via: X-Forwarded-Host: (1.2.3.4|1.2.3.5)." +
                "Nesse caso os requests de 1.2.3.4 e 1.2.3.5 são de uma fonte confiável.");
        property.setDefaultValue("");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setType(STRING_TYPE);
        property.setName(FORCE_WAUTHN_FOR_HTTP_HEADER);
        property.setLabel("Exige U2F pelo Header");
        property.setHelpText("O U2F é exigido se um header do request HTTP atende um determinado padrão.");
        property.setDefaultValue("");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setType(LIST_TYPE);
        property.setName(DEFAULT_WAUTHN_OUTCOME);
        property.setLabel("Tratamento default");
        property.setOptions(asList(SKIP, FORCE));
        property.setHelpText("O que fazer se nenhuma regra anterior é usada.");
        configProperties.add(property);

//////////////////////

    }

    public boolean isUserSetupAllowed() {
        return true;
    }

    public Authenticator create(KeycloakSession keycloakSession) {
        logger.debug("Creating Webauthn Authenticator");
        return SINGLETON;
    }

    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    public void init(Config.Scope scope) {
        logger.info("Registering Factory for Webauthn Login");
    }

    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

    }

    public void close() {

    }

    public String getId() {
        return PROVIDER_ID;
    }

    public String getDisplayType() {
        return "Webauthn Login";
    }

    public String getReferenceCategory() {
        return "Webauthn Login";
    }

    public boolean isConfigurable() {
        return true;
    }

    public String getHelpText() {
        return "Webauthn Login";
    }

    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }
}
