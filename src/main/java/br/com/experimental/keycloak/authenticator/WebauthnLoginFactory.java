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
import static org.keycloak.provider.ProviderConfigProperty.BOOLEAN_TYPE;
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

    static final String CONVEYANCE_PREFERENCE = "conveyancePreference";
    static final String USER_VERIFICATION = "userVerification";
    static final String ATTACHMENT_TYPE = "attachmentType";
    static final String EXCLUDE_CREDENTIALS = "excludeCredentials";
    static final String REQUIRE_RESIDENT_KEY = "requireResidentKey";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();
    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.OPTIONAL,
            AuthenticationExecutionModel.Requirement.DISABLED};

    static {
        ProviderConfigProperty property;

        property = new ProviderConfigProperty();
        property.setType(STRING_TYPE);
        property.setName(FORCE_WAUTHN_FOR_CLIENT);
        property.setLabel("Requires Webauthn for clients");
        property.setHelpText("Webauthn will be required for clients in the list (comma separated). " +
                "Use * for all clients. " +
                "If you want to omit a specific client, please enter it preceded by a \"-\".");
        property.setDefaultValue("");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setType(STRING_TYPE);
        property.setName(FORCE_WAUTHN_FOR_CLIENT_EXCEPTION);
        property.setLabel("Requires Webauthn except for clients in the list");
        property.setHelpText("Webauthn will be required for users who has Webauthn configured, except if clientId" +
                " is in the list.");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setType(STRING_TYPE);
        property.setName(WAUTHN_CONTROL_USER_ATTRIBUTE);
        property.setLabel("User attribute");
        property.setHelpText("Attribute that controls webauthn use. " +
                "If attribute value is 'force', Webauthn is required. " +
                "If value is 'skip', Webauthn is ignored.");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setType(STRING_TYPE);
        property.setName(FORCE_WAUTHN_ROLE);
        property.setLabel("Webauthn for Roles");
        property.setHelpText("Webauthn will be required for Roles in the list. Use * for all of the Roles." +
                "If you want to omit a specific role, please enter it preceded by a \"-\".");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setType(STRING_TYPE);
        property.setName(SKIP_WAUTHN_FOR_HTTP_HEADER);
        property.setLabel("Does not require Webauthn by Header");
        property.setHelpText("Webauthn is not required if a HTTP header has a specifc pattern." +
                "Can be used to specify trusted networks via: X-Forwarded-Host: (1.2.3.4|1.2.3.5)." +
                "In this case requests from 1.2.3.4 e 1.2.3.5 are realiable.");
        property.setDefaultValue("");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setType(STRING_TYPE);
        property.setName(FORCE_WAUTHN_FOR_HTTP_HEADER);
        property.setLabel("Requires Webauthn by Header");
        property.setHelpText("Webauthn is required if a HTTP header has a specifc pattern.");
        property.setDefaultValue("");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setType(LIST_TYPE);
        property.setName(DEFAULT_WAUTHN_OUTCOME);
        property.setLabel("Default treatment");
        property.setOptions(asList(SKIP, FORCE));
        property.setHelpText("What to do if no previous rule is used.");
        configProperties.add(property);

        ////// advanced options webauthn

        property = new ProviderConfigProperty();
        property.setType(LIST_TYPE);
        property.setName(CONVEYANCE_PREFERENCE);
        property.setLabel("Conveyance Preference");
        property.setOptions(asList("none", "indirect", "direct"));
        property.setHelpText("See webauthn reference.");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setType(LIST_TYPE);
        property.setName(USER_VERIFICATION);
        property.setLabel("User Verification");
        property.setOptions(asList("none", "required", "preferred", "discouraged"));
        property.setHelpText("See webauthn reference.");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setType(LIST_TYPE);
        property.setName(ATTACHMENT_TYPE);
        property.setLabel("Attachment Type");
        property.setOptions(asList("none", "platform", "cross-platform"));
        property.setHelpText("See webauthn reference.");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setType(BOOLEAN_TYPE);
        property.setName(EXCLUDE_CREDENTIALS);
        property.setLabel("Exclude Credentials");
        property.setHelpText("See webauthn reference.");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setType(BOOLEAN_TYPE);
        property.setName(REQUIRE_RESIDENT_KEY);
        property.setLabel("require ResidentKey");
        property.setHelpText("See webauthn reference.");
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
