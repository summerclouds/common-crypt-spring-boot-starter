/**
 * Copyright (C) 2019 Mike Hummel (mh@mhus.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.summerclouds.common.crypt.util;

import java.util.HashMap;

import org.summerclouds.common.core.error.MException;
import org.summerclouds.common.core.util.SecureString;
import org.summerclouds.common.crypt.crypt.pem.PemBlock;
import org.summerclouds.common.crypt.crypt.pem.PemKey;
import org.summerclouds.common.crypt.crypt.pem.PemPriv;
import org.summerclouds.common.crypt.crypt.pem.PemPub;

import de.mhus.crypt.api.CryptException;
import de.mhus.crypt.api.PemProcessContext;

public class SimplePemProcessContext implements PemProcessContext {

    protected SecureString lastSecret;
    protected HashMap<String, PemBlock> keys = new HashMap<>();
    protected HashMap<String, SecureString> passphrases = new HashMap<>();
    protected PemBlock lastHash;
    private PemBlock lastValidated;

    @Override
    public void errorKeyNotFound(PemBlock block) throws CryptException {
        throw new CryptException("key not found", block);
    }

    @Override
    public PemPriv getPrivateKey(String privId) throws MException {
        PemBlock key = keys.get(privId);
        if (key == null) return null;
        return new PemKey(key);
    }

    @Override
    public String getPrivateIdForPublicKeyId(String pubId) throws CryptException {
        PemBlock pub = keys.get(pubId);
        if (pub == null) return null;
        return pub.getString(PemBlock.PRIV_ID, null);
    }

    @Override
    public SecureString getPassphrase(String privId, PemBlock block) throws CryptException {
        return passphrases.get(privId);
    }

    @Override
    public void foundSecret(PemBlock block, SecureString sec) {
        lastSecret = sec;
    }

    public SecureString getLastSecret() {
        return lastSecret;
    }

    @Override
    public void foundPublicKey(PemBlock block) {
        String id = block.getString(PemBlock.IDENT, null);
        if (id == null) return;
        keys.put(id, block);
    }

    @Override
    public void foundPrivateKey(PemBlock block) {
        String id = block.getString(PemBlock.IDENT, null);
        if (id == null) return;
        keys.put(id, block);
    }

    @Override
    public PemPub getPublicKey(String pubId) {
        PemBlock key = keys.get(pubId);
        if (key == null) return null;
        return new PemKey(key);
    }

    public void addPassphrase(String privId, SecureString passphrase) {
        passphrases.put(privId, passphrase);
    }

    @Override
    public void foundHash(PemBlock block) {
        lastHash = block;
    }

    public PemBlock getLastHash() {
        return lastHash;
    }

    @Override
    public void foundValidated(PemBlock block) {
        lastValidated = block;
    }

    public PemBlock getLastValidated() {
        return lastValidated;
    }
}
