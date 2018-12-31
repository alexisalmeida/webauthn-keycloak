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

import com.google.gson.Gson;

import java.util.logging.Logger;

public class PublicKeyCredential {
  private static final Logger Log = Logger.getLogger(PublicKeyCredential.class.getName());

  public String id;
  public String type;
  public byte[] rawId;
  AuthenticatorResponse response;
  String attestationResponse;

  /**
   * @param id
   * @param type
   * @param rawId
   * @param response
   */
  public PublicKeyCredential(String id, String type, byte[] rawId, AuthenticatorResponse response) {
    this.id = id;
    this.type = type;
    this.rawId = rawId;
    this.response = response;
  }

  public PublicKeyCredential(String valor) {
    if (valor!=null && !valor.isEmpty()) {
      Gson gson = new Gson();
      PublicKeyCredential stored = gson.fromJson(valor, PublicKeyCredential.class);

      this.id = stored.id;
      this.type = stored.type;
      this.rawId = stored.rawId;
      this.response = stored.response;
    }
  }

  /**
   *
   */
  public PublicKeyCredential() {}

  /**
   * @return the id
   */
  public String getId() {
    return id;
  }

  /**
   * @return the type
   */
  public String getType() {
    return type;
  }

  /**
   * @return the rawId
   */
  public byte[] getRawId() {
    return rawId;
  }

  public AttestationStatementEnum getAttestationType() {
    try {
      AuthenticatorAttestationResponse attRsp = (AuthenticatorAttestationResponse) response;
      AttestationStatement attStmt = attRsp.decodedObject.getAttestationStatement();
      if (attStmt instanceof AndroidSafetyNetAttestationStatement) {
        return AttestationStatementEnum.ANDROIDSAFETYNET;
      } else if (attStmt instanceof FidoU2fAttestationStatement) {
        return AttestationStatementEnum.FIDOU2F;
      } else if (attStmt instanceof PackedAttestationStatement) {
        return AttestationStatementEnum.PACKED;
      } else if (attStmt instanceof NoneAttestationStatement) {
        return AttestationStatementEnum.NONE;
      }
    } catch (ClassCastException e) {
      return null;
    }
    return null;
  }

  /**
   * @return the response
   */
  public AuthenticatorResponse getResponse() {
    return response;
  }

  public String getAttestationResponse() {
    return attestationResponse;
  }

  public void setAttestationResponse(String attestationResponse) {
    this.attestationResponse = attestationResponse;
  }

  /**
   * @return json encoded String representation of PublicKeyCredential
   */
  public String encode() {
    return new Gson().toJson(this);
  }

}
