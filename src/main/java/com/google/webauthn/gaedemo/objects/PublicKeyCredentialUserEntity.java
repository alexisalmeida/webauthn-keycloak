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
import com.google.gson.Gson;
import com.google.gson.JsonObject;

public class PublicKeyCredentialUserEntity extends PublicKeyCredentialEntity {
  protected String displayName;
  protected byte[] id;

  /**
   * @param displayName
   */
  public PublicKeyCredentialUserEntity(String displayName, byte[] id) {
    super();
    this.displayName = displayName;
    this.name = displayName;
    this.id = id;
  }

  public PublicKeyCredentialUserEntity(String saved) {
    super();

    Gson gson = new Gson();

    PublicKeyCredentialUserEntity pk = gson.fromJson(saved,PublicKeyCredentialUserEntity.class);

    this.displayName = pk.displayName;
    this.name = pk.displayName;
    this.id = pk.id;
  }

  /**
   * @return
   */
  @Override
  public JsonObject getJsonObject() {
    JsonObject superJson = super.getJsonObject();
    superJson.addProperty("displayName", displayName);
    superJson.addProperty("id", BaseEncoding.base64().encode(id));
    return superJson;
  }
}
