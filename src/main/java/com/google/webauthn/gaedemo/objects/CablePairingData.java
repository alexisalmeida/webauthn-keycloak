/*
 * Copyright 2018 Google Inc. All Rights Reserved.
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
 *
 */

package com.google.webauthn.gaedemo.objects;

import com.google.gson.Gson;

public class CablePairingData {
    public int version;
    public byte[] irk;
    public byte[] lk;

    public CablePairingData(int version, byte[] irk, byte[] lk) {
        this.version = version;
        this.irk = irk;
        this.lk = lk;
    }

    public CablePairingData(String valor) {
        if (valor!=null && !valor.isEmpty()) {
            Gson gson = new Gson();
            CablePairingData stored = gson.fromJson(valor, CablePairingData.class);

            this.version = stored.version;
            this.irk = stored.irk;
            this.lk = stored.lk;
        }
    }

    public CablePairingData() {}
}
