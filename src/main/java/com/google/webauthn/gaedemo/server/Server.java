// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.webauthn.gaedemo.server;

import co.nstant.in.cbor.CborException;
import com.google.common.base.Splitter;
import com.google.common.collect.Iterables;
import com.google.common.io.BaseEncoding;
import com.google.common.primitives.Bytes;
import com.google.gson.*;
import com.google.webauthn.gaedemo.crypto.AlgorithmIdentifierMapper;
import com.google.webauthn.gaedemo.crypto.Crypto;
import com.google.webauthn.gaedemo.exceptions.ResponseException;
import com.google.webauthn.gaedemo.exceptions.WebAuthnException;
import com.google.webauthn.gaedemo.objects.*;
import com.google.webauthn.gaedemo.storage.SessionData;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.ClientSessionModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;

import java.security.PublicKey;
import java.util.*;
import java.util.logging.Logger;

import br.com.experimental.keycloak.authenticator.WebauthnCredentialProvider;

public abstract class Server {

    private static final Logger Log = Logger.getLogger(Server.class.getName());

    public static final String U2F_SESSION_DATA = "u2f-session-data";

    public static void verifySessionAndChallenge(AuthenticatorResponse assertionResponse,
                                                 ClientSessionModel authenticationSession,
                                                 String sessionId) throws ResponseException {
        Log.info("-- Verifying provided session and challenge data --");
        // TODO: when it's calling from an Android application via Endpoints API, the session ID
        // is temporarily null for now.
        if (sessionId == null) {
            return;
        }

        SessionData sessao = new SessionData(authenticationSession.getUserSessionNotes().get(U2F_SESSION_DATA));

        // Session.getChallenge is a base64-encoded string
        byte[] sessionChallenge = BaseEncoding.base64().decode(sessao.getChallenge());
        // assertionResponse.getClientData().getChallenge() is a base64url-encoded string
        byte[] clientSessionChallenge =
                BaseEncoding.base64Url().decode(assertionResponse.getClientData().getChallenge());
        if (!Arrays.equals(sessionChallenge, clientSessionChallenge)) {
            throw new ResponseException("Returned challenge incorrect");
        }
        Log.info("Successfully verified session and challenge data");
    }

    public static CredentialModel validateAndFindCredential(PublicKeyCredential cred, AuthenticationFlowContext contexto,
                                                            String sessionId) throws ResponseException {
        if (!(cred.getResponse() instanceof AuthenticatorAssertionResponse)) {
            throw new ResponseException("Invalid authenticator response");
        }

        AuthenticatorAssertionResponse assertionResponse = (AuthenticatorAssertionResponse) cred.getResponse();

        RealmModel realm = contexto.getRealm();
        UserModel user = contexto.getUser();

        List<CredentialModel> savedCreds = contexto.getSession().userCredentialManager()
                .getStoredCredentialsByType(realm, user, WebauthnCredentialProvider.TYPE);
        if (savedCreds == null || savedCreds.size() == 0) {
            throw new ResponseException("No credentials registered for this user");
        }

        try {
            verifySessionAndChallenge(assertionResponse, contexto.getClientSession(), sessionId);
        } catch (ResponseException e1) {
            throw new ResponseException("Unable to verify session and challenge data");
        }

        CredentialModel credential = null;
        for (CredentialModel saved : savedCreds) {
            JsonObject json = new JsonParser().parse(saved.getValue()).getAsJsonObject();

            PublicKeyCredential credSaved = new PublicKeyCredential(json.toString());

            if (credSaved.getId().equals(cred.getId())) {
                credential = saved;
                break;
            }
        }

        if (credential == null) {
            Log.info("Credential not registered with this user");
            throw new ResponseException("Received response from credential not associated with user");
        }

        return credential;
    }

    /**
     * @param cred

     * @throws Exception
     */
    public static void verifyAssertion(PublicKeyCredential cred, CredentialModel savedCredential) throws Exception {
        AuthenticatorAssertionResponse assertionResponse =
                (AuthenticatorAssertionResponse) cred.getResponse();

        Log.info("-- Verifying signature --");
        if (!(savedCredential.getType().equals(WebauthnCredentialProvider.TYPE))) {
            throw new Exception("Stored attestation missing");
        }

        JsonObject json = new JsonParser().parse(savedCredential.getValue()).getAsJsonObject();

        AuthenticatorAttestationResponse storedAttData = new AuthenticatorAttestationResponse(json.get("attestationResponse").getAsString());

        try {
            PublicKey publicKey;
            if (storedAttData.decodedObject.getAuthenticatorData().getAttData().getPublicKey() instanceof EccKey) {
                publicKey = Crypto.getECPublicKey((EccKey) storedAttData.decodedObject.getAuthenticatorData().getAttData().getPublicKey());
            } else {
                publicKey = Crypto.getRSAPublicKey((RsaKey) storedAttData.decodedObject.getAuthenticatorData().getAttData().getPublicKey());
            }

            byte[] clientDataHash = Crypto.sha256Digest(assertionResponse.getClientDataBytes());

            byte[] signedBytes;
            // concat of aData (authDataBytes) and hash of cData (clientDataHash)
            try {
                signedBytes = Bytes.concat(assertionResponse.getAuthDataBytes(), clientDataHash);
            } catch (NullPointerException e) {
                try {
                    signedBytes = Bytes.concat(assertionResponse.getAuthenticatorData().encode(),
                            clientDataHash);
                } catch (CborException e1) {
                    throw new Exception("Authenticator data invalid", e);
                }
            }
            String signatureAlgorithm = AlgorithmIdentifierMapper.get(
                    storedAttData.decodedObject.getAuthenticatorData().getAttData().getPublicKey().getAlg())
                    .getJavaAlgorithm();
            if (!Crypto.verifySignature(publicKey, signedBytes, assertionResponse.getSignature(),
                    signatureAlgorithm)) {
                throw new Exception("Signature invalid");
            }
        } catch (WebAuthnException e) {
            throw new Exception("Failure while verifying signature");
        }

        Integer cont = savedCredential.getCounter();
        if (Integer.compareUnsigned(assertionResponse.getAuthenticatorData().getSignCount(), cont) <= 0) {
            throw new Exception("Sign count invalid");
        }


        savedCredential.setCounter(assertionResponse.getAuthenticatorData().getSignCount());

        Log.info("Signature verified");
    }

    public static JsonObject startRegistration(RequiredActionContext contexto)
            throws Exception {

        Log.info("*** Start Registration ***");

        UserModel user = contexto.getUser();

        String host = contexto.getActionUrl().getHost();
        String rpId = Iterables.get(Splitter.on(':').split(host), 0);
        String rpName = contexto.getRealm().getName();

        PublicKeyCredentialCreationOptions options =
                new PublicKeyCredentialCreationOptions(user.getUsername(), user.getId(), rpId, rpName);


        //TODO get advanced configuration from provider config
            /*
            String hasAdvanced = context.getHttpRequest().getFormParameters().getFirst("advanced");
            if (hasAdvanced.equals("true")) {
                parseAdvancedOptions(context.getHttpRequest().getFormParameters().getFirst("advancedOptions"), options);
            }
            */

        SessionData session = new SessionData(options.challenge, rpId);

        JsonObject sessionJson = session.getJsonObject();
        JsonObject optionsJson = options.getJsonObject();
        optionsJson.add("session", sessionJson);

        contexto.getClientSession().setUserSessionNote(U2F_SESSION_DATA, sessionJson.toString());

        return optionsJson;

    }

    public static PublicKeyCredential finishRegistration(RequiredActionContext contexto,
                                                         String data, String session)
            throws Exception {
        String credentialId = null;
        String type = null;
        JsonElement makeCredentialResponse = null;
        String currentUser = contexto.getUser().getUsername();

        Log.info("*** Finish Registration ***");


        try {
            JsonObject json = new JsonParser().parse(data).getAsJsonObject();
            JsonElement idJson = json.get("id");
            if (idJson != null) {
                credentialId = idJson.getAsString();
            }
            JsonElement typeJson = json.get("type");
            if (typeJson != null) {
                type = typeJson.getAsString();
            }
            makeCredentialResponse = json.get("response");
        } catch (IllegalStateException e) {
            throw new Exception("Passed data not a json object");
        } catch (ClassCastException e) {
            throw new Exception("Invalid input");
        } catch (JsonParseException e) {
            throw new Exception("Input not valid json");
        }

        AuthenticatorAttestationResponse attestation = null;
        try {
            attestation = new AuthenticatorAttestationResponse(makeCredentialResponse);
        } catch (ResponseException e) {
            throw new Exception(e.toString());
        }

        // Recoding of credential ID is needed, because the ID from HTTP servlet request doesn't support
        // padding.
        String credentialIdRecoded = BaseEncoding.base64Url().encode(
                BaseEncoding.base64Url().decode(credentialId));

        PublicKeyCredential cred = new PublicKeyCredential(credentialIdRecoded, type,
                BaseEncoding.base64Url().decode(credentialId), attestation);

        String domain = contexto.getActionUrl().getHost();
        String host = contexto.getActionUrl().getHost();
        String rpId = Iterables.get(Splitter.on(':').split(host), 0);
        //String rpName = contexto.getRealm().getName();

        switch (cred.getAttestationType()) {
            case FIDOU2F:
                U2fServer.registerCredential(contexto, cred, currentUser, session, domain, rpId);
                break;
            case ANDROIDSAFETYNET:
                AndroidSafetyNetServer.registerCredential(contexto, cred, currentUser, session, rpId);
                break;
            case PACKED:
                PackedServer.registerCredential(contexto, cred, currentUser, session, rpId);
                break;
            case NONE:
                break;
        }

        cred.setAttestationResponse(((AuthenticatorAttestationResponse)cred.getResponse()).encode());
        UserCredentialModel credentials = new UserCredentialModel();
        credentials.setType(WebauthnCredentialProvider.TYPE);
        credentials.setValue(cred.encode());

        Log.info("stored credential: " + cred.encode());

        contexto.getSession().userCredentialManager().updateCredential(contexto.getRealm(), contexto.getUser(), credentials);


        return cred;
    }


    private void parseAdvancedOptions(RequiredActionContext contexto, String jsonString, PublicKeyCredentialCreationOptions options) {
        RealmModel realm = contexto.getRealm();
        UserModel user = contexto.getUser();
        JsonElement jsonElement = new JsonParser().parse(jsonString);
        JsonObject jsonObject = jsonElement.getAsJsonObject();
        Set<Map.Entry<String, JsonElement>> entries = jsonObject.entrySet();

        boolean rk = false;
        boolean excludeCredentials = false;
        UserVerificationRequirement uv = null;
        AuthenticatorAttachment attachment = null;
        for (Map.Entry<String, JsonElement> entry : entries) {
            if (entry.getKey().equals("requireResidentKey")) {
                rk = entry.getValue().getAsBoolean();
            } else if (entry.getKey().equals("excludeCredentials")) {
                excludeCredentials = entry.getValue().getAsBoolean();

                if (excludeCredentials) {
                    List<PublicKeyCredentialDescriptor> credentials = new ArrayList<>();

                    List<CredentialModel> savedCreds = contexto.getSession().userCredentialManager()
                            .getStoredCredentialsByType(realm, user, WebauthnCredentialProvider.TYPE);

                    for (CredentialModel c : savedCreds) {
                        credentials.add(convertCredentialToCredentialDescriptor(c));
                    }
                    options.setExcludeCredentials(credentials);
                }
            } else if (entry.getKey().equals("userVerification")) {
                uv = UserVerificationRequirement.decode(entry.getValue().getAsString());
            } else if (entry.getKey().equals("authenticatorAttachment")) {
                attachment = AuthenticatorAttachment.decode(entry.getValue().getAsString());
            } else if (entry.getKey().equals("attestationConveyancePreference")) {
                AttestationConveyancePreference conveyance =
                        AttestationConveyancePreference.decode(entry.getValue().getAsString());
                options.setAttestationConveyancePreference(conveyance);
            }
        }

        options.setCriteria(new AuthenticatorSelectionCriteria(attachment, rk, uv));
    }

    private PublicKeyCredentialDescriptor convertCredentialToCredentialDescriptor(CredentialModel c) {
        PublicKeyCredentialType type = PublicKeyCredentialType.PUBLIC_KEY;
        byte[] id = c.getId().getBytes();

        return new PublicKeyCredentialDescriptor(type, id, null);
    }

    public static JsonObject startAssertion(AuthenticationFlowContext contexto)
            throws Exception {
        JsonObject assertionJson = null;

        Log.info("*** Start Assertion ***");
        try {
            UserModel user = contexto.getUser();
            RealmModel realm = contexto.getRealm();

            //String rpId = contexto.getHttpRequest().getUri().getBaseUri().getHost();
            //String rpId = contexto.getActionUrl().getHost();
            String host = contexto.getActionUrl().getHost();
            String rpId = Iterables.get(Splitter.on(':').split(host), 0);

            PublicKeyCredentialRequestOptions assertion = new PublicKeyCredentialRequestOptions(rpId);
            SessionData session = new SessionData(assertion.challenge, rpId);

            JsonObject sessionJson = session.getJsonObject();
            assertion.populateAllowList(contexto.getSession().userCredentialManager()
                    .getStoredCredentialsByType(realm, user, WebauthnCredentialProvider.TYPE));

            assertionJson = assertion.getJsonObject();
            assertionJson.add("session", sessionJson);

            contexto.getClientSession().setUserSessionNote(U2F_SESSION_DATA, sessionJson.toString());

        } catch(Exception e) {
            e.printStackTrace();
        }

        return assertionJson;
    }
    public static CredentialModel finishAssertion(AuthenticationFlowContext contexto,
                                             String data, String session)
            throws Exception {

        Log.info("*** Finish Assertion ***");
        String credentialId = null;
        String type = null;
        JsonElement assertionJson = null;

        try {
            JsonObject json = new JsonParser().parse(data).getAsJsonObject();
            JsonElement idJson = json.get("id");
            if (idJson != null) {
                credentialId = idJson.getAsString();
            }
            JsonElement typeJson = json.get("type");
            if (typeJson != null) {
                type = typeJson.getAsString();
            }
            assertionJson = json.get("response");
            if (assertionJson == null) {
                throw new Exception("Missing element 'response'");
            }
        } catch (IllegalStateException e) {
            throw new Exception("Passed data not a json object");
        } catch (ClassCastException e) {
            throw new Exception("Invalid input");
        } catch (JsonParseException e) {
            throw new Exception("Input not valid json");
        }

        AuthenticatorAssertionResponse assertion = null;
        try {
            assertion = new AuthenticatorAssertionResponse(assertionJson);
        } catch (ResponseException e) {
            throw new Exception(e.toString());
        }

        // Recoding of credential ID is needed, because the ID from HTTP servlet request doesn't support
        // padding.
        String credentialIdRecoded = BaseEncoding.base64Url().encode(
                BaseEncoding.base64Url().decode(credentialId));
        PublicKeyCredential cred = new PublicKeyCredential(credentialIdRecoded, type,
                BaseEncoding.base64Url().decode(credentialId), assertion);

        CredentialModel savedCredential;
        try {
            savedCredential = validateAndFindCredential(cred, contexto, session);
        } catch (ResponseException e) {
            e.printStackTrace();
            throw new Exception("Unable to validate assertion", e);
        }

        verifyAssertion(cred, savedCredential);

        return  savedCredential;
    }
}