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

package com.google.webauthn.gaedemo.storage;

import com.google.common.io.BaseEncoding;
import com.google.gson.JsonObject;

public class AttestationSessionData {
  String user;
  public Long id;

  String challenge;
  String origin;

  public AttestationSessionData(byte[] challenge, String origin) {
    this.challenge = BaseEncoding.base64().encode(challenge);
    this.origin = origin;
  }
  
  public JsonObject getJsonObject() {
    JsonObject result = new JsonObject();
    result.addProperty("challenge", challenge);
    result.addProperty("origin", origin);
    return result;
  }

}
