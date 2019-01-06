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
import com.google.common.primitives.Bytes;
import com.google.webauthn.gaedemo.crypto.Crypto;
import com.google.webauthn.gaedemo.crypto.OfflineVerify;
import com.google.webauthn.gaedemo.crypto.OfflineVerify.AttestationStatement;
import com.google.webauthn.gaedemo.exceptions.ResponseException;
import com.google.webauthn.gaedemo.exceptions.WebAuthnException;
import com.google.webauthn.gaedemo.objects.*;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.credential.CredentialModel;
import br.com.experimental.keycloak.authenticator.WebauthnCredentialProvider;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

public class AndroidSafetyNetServer extends Server {
  private static final Logger Log = Logger.getLogger(AndroidSafetyNetServer.class.getName());

  /**
   * @param cred
   * @param rpId
   * @param session
   * @param currentUser
   * @throws Exception
   */
  public static void registerCredential(RequiredActionContext contexto, PublicKeyCredential cred, String currentUser,
                                        String session, String rpId) throws Exception {

    if (!(cred.getResponse() instanceof AuthenticatorAttestationResponse)) {
      throw new Exception("Invalid response structure");
    }

    AuthenticatorAttestationResponse attResponse =
        (AuthenticatorAttestationResponse) cred.getResponse();

    RealmModel realm = contexto.getRealm();
    UserModel user = contexto.getUser();

    List<CredentialModel> savedCreds = contexto.getSession().userCredentialManager()
            .getStoredCredentialsByType(realm, user, WebauthnCredentialProvider.TYPE);
    for (CredentialModel c : savedCreds) {
      if (c.getId().equals(cred.id)) {
        throw new Exception("Credential already registered for this user");
      }
    }

    try {
      verifySessionAndChallenge(attResponse, contexto.getAuthenticationSession() , session);
    } catch (ResponseException e1) {
      throw new Exception("Unable to verify session and challenge data");
    }

    AndroidSafetyNetAttestationStatement attStmt =
        (AndroidSafetyNetAttestationStatement) attResponse.decodedObject.getAttestationStatement();

    AttestationStatement stmt =
        OfflineVerify.parseAndVerify(new String(attStmt.getResponse(), StandardCharsets.UTF_8));
    if (stmt == null) {
      Log.info("Failure: Failed to parse and verify the attestation statement.");
      throw new Exception("Failed to verify attestation statement");
    }

    byte[] clientDataHash = Crypto.sha256Digest(attResponse.getClientDataBytes());

    try {
      // Nonce was changed from [authenticatorData, clientDataHash] to
      // sha256 [authenticatorData, clientDataHash]
      // https://github.com/w3c/webauthn/pull/869
      byte[] expectedNonce = Crypto.sha256Digest(Bytes.concat(
          attResponse.getAttestationObject().getAuthenticatorData().encode(), clientDataHash));
      if (!Arrays.equals(expectedNonce, stmt.getNonce())) {
        // TODO(cpiper) Remove this hack.
        expectedNonce = Bytes.concat(
            attResponse.getAttestationObject().getAuthenticatorData().encode(), clientDataHash);
        if (!Arrays.equals(expectedNonce, stmt.getNonce())) {
          throw new Exception("Nonce does not match");
        }
        //
      }
    } catch (CborException e) {
      throw new Exception("Error encoding authdata");
    }

    /*
     * // Test devices won't pass this. if (!stmt.isCtsProfileMatch()) { throw new
     * ServletException("No cts profile match"); }
     */
  }

  // TODO Remove after switch to generic verification
  /**
   * @param cred
   * @param currentUser
   * @param sessionId
   * @throws Exception
   */
  public static void verifyAssertion(PublicKeyCredential cred, String currentUser, String sessionId,
      CredentialModel savedCredential) throws Exception {

    AuthenticatorAssertionResponse assertionResponse =
        (AuthenticatorAssertionResponse) cred.getResponse();

    Log.info("-- Verifying signature --");
    if (!(savedCredential.getType().equals(WebauthnCredentialProvider.TYPE))) {
      throw new Exception("Stored attestation missing");
    }
    AuthenticatorAttestationResponse storedAttData =
            new  AuthenticatorAttestationResponse(savedCredential.getValue());

    if (!(storedAttData.decodedObject.getAuthenticatorData().getAttData()
        .getPublicKey() instanceof EccKey)) {
      throw new Exception("Ecc key not provided");
    }

    EccKey publicKey =
        (EccKey) storedAttData.decodedObject.getAuthenticatorData().getAttData().getPublicKey();
    try {
      byte[] clientDataHash = Crypto.sha256Digest(assertionResponse.getClientDataBytes());
      byte[] signedBytes =
          Bytes.concat(assertionResponse.getAuthenticatorData().encode(), clientDataHash);
      if (!Crypto.verifySignature(Crypto.decodePublicKey(publicKey.getX(), publicKey.getY()),
          signedBytes, assertionResponse.getSignature())) {
        throw new Exception("Signature invalid");
      }
    } catch (WebAuthnException e) {
      throw new Exception("Failure while verifying signature", e);
    } catch (CborException e) {
      throw new Exception("Failure while verifying authenticator data");
    }

    if (Integer.compareUnsigned(assertionResponse.getAuthenticatorData().getSignCount(),
        savedCredential.getCounter()) <= 0 && savedCredential.getCounter() != 0) {
      throw new Exception("Sign count invalid");
    }

    savedCredential.setCounter(assertionResponse.getAuthenticatorData().getSignCount());

    Log.info("Signature verified");
  }
}
