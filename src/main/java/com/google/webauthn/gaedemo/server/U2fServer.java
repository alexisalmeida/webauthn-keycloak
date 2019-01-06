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

import com.google.common.primitives.Bytes;
import com.google.webauthn.gaedemo.crypto.Crypto;
import com.google.webauthn.gaedemo.exceptions.ResponseException;
import com.google.webauthn.gaedemo.exceptions.WebAuthnException;
import com.google.webauthn.gaedemo.objects.*;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.credential.CredentialModel;
import br.com.experimental.keycloak.authenticator.WebauthnCredentialProvider;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

public class U2fServer extends Server {

  private static final Logger Log = Logger.getLogger(U2fServer.class.getName());

  /**
   * @param cred

   * @throws Exception
   */
  @Deprecated
  public static void verifyAssertion(PublicKeyCredential cred, CredentialModel savedCredential) throws Exception {
    AuthenticatorAssertionResponse assertionResponse =
        (AuthenticatorAssertionResponse) cred.getResponse();

    Log.info("-- Verifying signature --");

    AuthenticatorAttestationResponse storedAttData = new AuthenticatorAttestationResponse(savedCredential.getValue());

    if (!(storedAttData.decodedObject.getAuthenticatorData().getAttData()
        .getPublicKey() instanceof EccKey)) {
      throw new Exception("U2f-capable key not provided");
    }

    EccKey publicKey =
        (EccKey) storedAttData.decodedObject.getAuthenticatorData().getAttData().getPublicKey();
    try {
      /*
       * U2F authentication signatures are signed over the concatenation of
       *
       * 32 byte application parameter hash
       *
       * 1 byte user presence
       *
       * 4 byte big-endian representation of the counter
       *
       * 32 byte challenge parameter (ie SHA256 hash of clientData)
       */
      byte[] clientDataHash = Crypto.sha256Digest(assertionResponse.getClientDataBytes());

      byte[] signedBytes =
          Bytes.concat(storedAttData.getAttestationObject().getAuthenticatorData().getRpIdHash(),
              new byte[] {
                  (assertionResponse.getAuthenticatorData().isUP() == true ? (byte) 1 : (byte) 0)},
              ByteBuffer.allocate(4).putInt(assertionResponse.getAuthenticatorData().getSignCount())
                  .array(),
              clientDataHash);
      if (!Crypto.verifySignature(Crypto.decodePublicKey(publicKey.getX(), publicKey.getY()),
          signedBytes, assertionResponse.getSignature())) {
        signedBytes[storedAttData.getAttestationObject().getAuthenticatorData()
            .getRpIdHash().length] = assertionResponse.getAuthenticatorData().getFlags();
        //TODO Remove this hack.
        if (!Crypto.verifySignature(Crypto.decodePublicKey(publicKey.getX(), publicKey.getY()),
            signedBytes, assertionResponse.getSignature())) {
          throw new Exception("Signature invalid");
        }
        //
      }
    } catch (WebAuthnException e) {
      throw new Exception("Failure while verifying signature");
    }

    if (Integer.compareUnsigned(assertionResponse.getAuthenticatorData().getSignCount(),
        savedCredential.getCounter()) <= 0) {
      throw new Exception("Sign count invalid");
    }

    savedCredential.setCounter(assertionResponse.getAuthenticatorData().getSignCount());

    Log.info("Signature verified");
  }

  /**
   * @param cred
   * @param currentUser
   * @param session
   * @param originString
   * @throws Exception
   */
  public static void registerCredential(RequiredActionContext contexto, PublicKeyCredential cred,
                                        String currentUser, String session, String originString,
                                        String rpId) throws Exception {

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
        throw new Exception("Credential already registerd for this user");
      }
    }

    try {
      verifySessionAndChallenge(attResponse, contexto.getAuthenticationSession(), session);
    } catch (ResponseException e1) {
      throw new Exception("Unable to verify session and challenge data", e1);
    }

    byte[] clientDataHash = Crypto.sha256Digest(attResponse.getClientDataBytes());

    byte[] rpIdHash = Crypto.sha256Digest(rpId.getBytes(StandardCharsets.UTF_8));

    if (!Arrays.equals(attResponse.getAttestationObject().getAuthenticatorData().getRpIdHash(),
        rpIdHash)) {
      throw new Exception("RPID hash incorrect");
    }

    if (!(attResponse.decodedObject.getAuthenticatorData().getAttData()
        .getPublicKey() instanceof EccKey)) {
      throw new Exception("U2f-capable key not provided");
    }

    FidoU2fAttestationStatement attStmt =
        (FidoU2fAttestationStatement) attResponse.decodedObject.getAttestationStatement();

    EccKey publicKey =
        (EccKey) attResponse.decodedObject.getAuthenticatorData().getAttData().getPublicKey();

    try {
      /*
       * U2F registration signatures are signed over the concatenation of
       *
       * 1 byte RFU (0)
       *
       * 32 byte application parameter hash
       *
       * 32 byte challenge parameter
       *
       * key handle
       *
       * 65 byte user public key represented as {0x4, X, Y}
       */
      byte[] signedBytes = Bytes.concat(new byte[] {0}, rpIdHash, clientDataHash, cred.rawId,
          new byte[] {0x04}, publicKey.getX(), publicKey.getY());

      // TODO Make attStmt.attestnCert an X509Certificate right off the
      // bat.
      DataInputStream inputStream =
          new DataInputStream(new ByteArrayInputStream(attStmt.attestnCert));
      X509Certificate attestationCertificate = (X509Certificate) CertificateFactory
          .getInstance("X.509").generateCertificate(inputStream);

      if (!Crypto.verifySignature(attestationCertificate, signedBytes, attStmt.sig)) {
        throw new Exception("Signature invalid");
      }
    } catch (CertificateException e) {
      throw new Exception("Error when parsing attestationCertificate");
    } catch (WebAuthnException e) {
      throw new Exception("Failure while verifying signature", e);
    }

    // TODO Check trust anchors
    // TODO Check if self-attestation(/is allowed)
    // TODO Check X.509 certs

  }

}
