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

package com.google.webauthn.gaedemo.objects;

import com.google.common.io.BaseEncoding;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.webauthn.gaedemo.crypto.Cable;
import com.google.webauthn.gaedemo.server.U2fServer;
import org.keycloak.credential.CredentialModel;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

public class PublicKeyCredentialRequestOptions {
    private static final Logger Log = Logger.getLogger(PublicKeyCredentialRequestOptions.class.getName());

    private static final int CHALLENGE_LENGTH = 32;
    private final SecureRandom random = new SecureRandom();

    // Required parameters
    public byte[] challenge;

    // Optional parameters
    public long timeout;
    public String rpId;
    protected ArrayList<PublicKeyCredentialDescriptor> allowCredentials;
    protected UserVerificationRequirement userVerification;
    AuthenticationExtensions extensions;
  

    /**
    * @param rpId
    */
    public PublicKeyCredentialRequestOptions(String rpId) {
        challenge = new byte[CHALLENGE_LENGTH];
        random.nextBytes(challenge);
        allowCredentials = new ArrayList<PublicKeyCredentialDescriptor>();
        this.rpId = rpId;
    }

  /**
   * @return JsonObject representation of PublicKeyCredentialRequestOptions
   */
    public JsonObject getJsonObject() {
        JsonObject result = new JsonObject();

        result.addProperty("challenge", BaseEncoding.base64().encode(challenge));
        if (timeout > 0) {
            result.addProperty("timeout", timeout);
        }
        result.addProperty("rpId", rpId);
        JsonArray allowCredentials = new JsonArray();
        for (PublicKeyCredentialDescriptor credential : this.allowCredentials) {
            allowCredentials.add(credential.getJsonObject());
        }
        result.add("allowCredentials", allowCredentials);
        if (extensions != null) {
            result.add("extensions", extensions.getJsonObject());
        }

        return result;
    }

  /**
   * @param credentialList
   */
    public void populateAllowList(List<CredentialModel> credentialList) {

        for (CredentialModel c : credentialList) {
            JsonObject json = new JsonParser().parse(c.getValue()).getAsJsonObject();
            PublicKeyCredential storedCred = new PublicKeyCredential(json.toString());

            if (storedCred == null)
                continue;

            PublicKeyCredentialDescriptor pkcd =
              new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, storedCred.rawId);

            allowCredentials.add(pkcd);

            Cable cableCrypto = new Cable();

            String storedConfig = c.getConfig().getFirst("CablePairingData");

            if (storedConfig != null && !storedConfig.isEmpty()) {
                CablePairingData cablePairingData = new CablePairingData(storedConfig);

                if (extensions == null) {
                    extensions = new AuthenticationExtensions();
                }
                extensions.addCableSessionData(cableCrypto.generateSessionData(cablePairingData));
            }
        }
    }
}
