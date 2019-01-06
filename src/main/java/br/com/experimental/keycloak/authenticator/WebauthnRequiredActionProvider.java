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
import com.google.webauthn.gaedemo.server.Server;
import org.jboss.logging.Logger;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.forms.login.freemarker.model.UrlBean;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class WebauthnRequiredActionProvider implements RequiredActionProvider {

    private static final Logger logger = Logger.getLogger(WebauthnRequiredActionProvider.class);

    private static final String atrib2f_fido_register = "2f_fido_reg";

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        logger.debugv("Sending registration, session: {0}", context.getAuthenticationSession().getParentSession().getId());
        //logger.info(String.format("Sending registration, session: {%s}", context.getAuthenticationSession().getId()));

        try {

            JsonObject optionsJson = Server.startRegistration(context);

            logger.info("Base URI: " + context.getSession().getContext().getUri().getBaseUri());
            Response challenge = context.form()
                    //.setAttribute("url", new UrlBean(context.getRealm(), context.getSession().themes().getTheme(Theme.Type.LOGIN), context.getSession().getContext().getUri().getBaseUri(), context.getActionUrl()))
                    .setAttribute("url", new UrlBean(context.getRealm(), null,
                            context.getSession().getContext().getUri().getBaseUri(), context.getActionUrl()))
                    .setAttribute("request", optionsJson.toString())
                    .createForm("fido-webauthn-register.ftl");

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

            context.getAuthenticationSession().setUserSessionNote(atrib2f_fido_register, "true");

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

}
