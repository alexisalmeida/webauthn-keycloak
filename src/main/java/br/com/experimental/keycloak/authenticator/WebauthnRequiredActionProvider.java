/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package br.com.experimental.keycloak.authenticator;

import com.google.gson.JsonObject;
import com.google.webauthn.gaedemo.server.AdvancedOptions;
import com.google.webauthn.gaedemo.server.Server;
import org.jboss.logging.Logger;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.forms.login.freemarker.model.UrlBean;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.List;

import static br.com.experimental.keycloak.authenticator.WebauthnLoginFactory.*;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class WebauthnRequiredActionProvider implements RequiredActionProvider {

    private static final Logger logger = Logger.getLogger(WebauthnRequiredActionProvider.class);

    private static final String atrib_webauthn_register = "webauthn_reg";

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        logger.debugv("Sending registration, session: {0}", context.getAuthenticationSession().getParentSession().getId());
        //logger.info(String.format("Sending registration, session: {%s}", context.getAuthenticationSession().getId()));

        try {
            AuthenticatorConfigModel configModel = getConfig(context.getSession(), WebauthnLoginFactory.PROVIDER_ID);
            logger.info("config: " + configModel);
            AdvancedOptions advancedOptions = new AdvancedOptions();

            advancedOptions.setConveyancePreference(configModel.getConfig().get(CONVEYANCE_PREFERENCE));
            advancedOptions.setUserVerification(configModel.getConfig().get(USER_VERIFICATION));
            advancedOptions.setAttachmentType(configModel.getConfig().get(ATTACHMENT_TYPE));
            advancedOptions.setExcludeCredentials(Boolean.getBoolean(configModel.getConfig().get(EXCLUDE_CREDENTIALS)));
            advancedOptions.setRequireResidentKey(Boolean.getBoolean(configModel.getConfig().get(REQUIRE_RESIDENT_KEY)));

            JsonObject optionsJson = Server.startRegistration(context, advancedOptions);

            logger.info("Base URI: " + context.getSession().getContext().getUri().getBaseUri());
            Response challenge = context.form()
                    //.setAttribute("url", new UrlBean(context.getRealm(), context.getSession().themes().getTheme(Theme.Type.LOGIN), context.getSession().getContext().getUri().getBaseUri(), context.getActionUrl()))
                    .setAttribute("url", new UrlBean(context.getRealm(), null,
                            context.getSession().getContext().getUri().getBaseUri(), context.getActionUrl()))
                    .setAttribute("request", optionsJson.toString())
                    .createForm("register-webauthn.ftl");

            context.challenge(challenge);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void processAction(RequiredActionContext context) {
        logger.info(String.format("Finish registration, session: {%s}", context.getAuthenticationSession().getParentSession().getId()));

        try {
            MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

            String data = formData.getFirst("data");
            String session = formData.getFirst("session");

            Server.finishRegistration(context, data, session);

            context.getAuthenticationSession().setUserSessionNote(atrib_webauthn_register, "true");

            context.success();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
    }

    @Override
    public void close() {
    }

    private AuthenticatorConfigModel getConfig(KeycloakSession session, String providerId) {
        logger.info("Getting config for: " + providerId);
        AuthenticatorConfigModel configModel = null;

        RealmModel realm = session.getContext().getRealm();
        String flowId = realm.getBrowserFlow().getId();

        return getConfig(realm, flowId, providerId);

    }

    private AuthenticatorConfigModel getConfig(RealmModel realm, String flowId, String providerId) {
        logger.info("Getting config for: " + flowId);

        AuthenticatorConfigModel configModel = null;

        List<AuthenticationExecutionModel> laem = realm.getAuthenticationExecutions(flowId);

        for (AuthenticationExecutionModel aem : laem) {
            logger.info("aem: " + String.format("%s, %s, %s, %s", aem.getFlowId(), aem.getId(),
                    aem.isEnabled(),aem.isAuthenticatorFlow()));
            if (aem.isAuthenticatorFlow()) {
                logger.info("flow: " + aem.getFlowId());
                configModel = getConfig(realm, aem.getFlowId(), providerId);
                if (configModel!= null) return configModel;
            } else if (aem.getAuthenticator() != null && aem.getAuthenticator().equals(providerId)) {
                logger.info("authenticator: " + aem.getAuthenticator());
                configModel = realm.getAuthenticatorConfigById(aem.getAuthenticatorConfig());
                break;
            }
        }
        return configModel;
    }

}
