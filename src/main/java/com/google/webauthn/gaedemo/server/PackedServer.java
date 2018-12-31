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
import com.google.webauthn.gaedemo.crypto.AlgorithmIdentifierMapper;
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
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;


public class PackedServer extends Server {

  private static final Logger Log = Logger.getLogger(PackedServer.class.getName());

  /**
   * @param cred
   * @throws Exception
   */
  @Deprecated
  public static void verifyAssertion(PublicKeyCredential cred, CredentialModel savedCredential) throws Exception {
    AuthenticatorAssertionResponse assertionResponse =
        (AuthenticatorAssertionResponse) cred.getResponse();

    Log.info("-- Verifying signature --");

    AuthenticatorAttestationResponse storedAttData =
            new AuthenticatorAttestationResponse(savedCredential.getValue());

    if (!(storedAttData.decodedObject.getAuthenticatorData().getAttData()
        .getPublicKey() instanceof EccKey)) {
      throw new Exception("U2f-capable key not provided");
    }



    // if (Integer.compareUnsigned(assertionResponse.getAuthenticatorData().getSignCount(),
    // savedCredential.getSignCount()) <= 0) {
    // throw new ServletException("Sign count invalid");
    // }

    savedCredential.setCounter(assertionResponse.getAuthenticatorData().getSignCount());

    Log.info("Signature verified");
  }

  /**
   * @param cred
   * @param currentUser
   * @param session
   * @param origin
   * @throws Exception
   */
  public static void registerCredential(RequiredActionContext contexto, PublicKeyCredential cred,
                                        String currentUser, String session, String origin) throws Exception {

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
      verifySessionAndChallenge(attResponse, contexto.getClientSession(), session);
    } catch (ResponseException e1) {
      throw new Exception("Unable to verify session and challenge data", e1);
    }

    byte[] clientDataHash = Crypto.sha256Digest(attResponse.getClientDataBytes());

    byte[] rpIdHash = Crypto.sha256Digest(origin.getBytes(StandardCharsets.UTF_8));

    if (!Arrays.equals(attResponse.getAttestationObject().getAuthenticatorData().getRpIdHash(),
        rpIdHash)) {
      throw new Exception("RPID hash incorrect");
    }

    if (!(attResponse.decodedObject.getAuthenticatorData().getAttData()
        .getPublicKey() instanceof EccKey)
        && !(attResponse.decodedObject.getAuthenticatorData().getAttData()
            .getPublicKey() instanceof RsaKey)) {
      throw new Exception("Supported key not provided");
    }

    PackedAttestationStatement attStmt =
        (PackedAttestationStatement) attResponse.decodedObject.getAttestationStatement();

    try {
      /*
       * Signatures are signed over the concatenation of Authenticator data and Client Data Hash
       */
      byte[] signedBytes =
          Bytes.concat(attResponse.decodedObject.getAuthenticatorData().encode(), clientDataHash);

      StringBuilder buf = new StringBuilder();
      for (byte b : signedBytes) {
        buf.append(String.format("%02X ", b));
      }

      Log.info("Signed bytes: " + buf.toString());

      String signatureAlgorithm;
      try {
        signatureAlgorithm = AlgorithmIdentifierMapper.get(
            attResponse.decodedObject.getAuthenticatorData().getAttData().getPublicKey().getAlg())
            .getJavaAlgorithm();
      } catch (Exception e) {
        // Default to ES256
        signatureAlgorithm = "SHA256withECDSA";
      }

      // TODO Make attStmt.attestnCert an X509Certificate right off the
      // bat.
      if (attStmt.attestnCert instanceof byte[]) {
        DataInputStream inputStream =
            new DataInputStream(new ByteArrayInputStream(attStmt.attestnCert));
        X509Certificate attestationCertificate = (X509Certificate) CertificateFactory
            .getInstance("X.509").generateCertificate(inputStream);

        if (!Crypto.verifySignature(attestationCertificate, signedBytes, attStmt.sig,
            signatureAlgorithm)) {
          throw new Exception("Signature invalid");
        }
      } else {
        // Self-attestation.
        if (!signatureAlgorithm
            .equals(AlgorithmIdentifierMapper.get(attStmt.alg).getJavaAlgorithm())) {
          throw new Exception("Algorithm mismatch");
        }

        PublicKey publicKey;
        if (attResponse.decodedObject.getAuthenticatorData().getAttData()
            .getPublicKey() instanceof EccKey) {
          publicKey = Crypto.getECPublicKey((EccKey) attResponse.decodedObject
              .getAuthenticatorData().getAttData().getPublicKey());
        } else {
          throw new Exception("Public Key not supported");
        }
        if (!Crypto.verifySignature(publicKey, signedBytes, attStmt.sig, signatureAlgorithm)) {
          throw new Exception("Signature invalid");
        }
      }
    } catch (CertificateException e) {
      throw new Exception("Error when parsing attestationCertificate");
    } catch (WebAuthnException e) {
      throw new Exception("Failure while verifying signature", e);
    } catch (CborException e) {
      throw new Exception("Unable to reencode authenticator data");
    }

    // TODO Check trust anchors
    // TODO Check X.509 certs

  }

}
