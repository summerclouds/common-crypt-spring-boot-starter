/**
 * Copyright (C) 2022 Mike Hummel (mh@mhus.de)
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
package org.summerclouds.common.crypt.bc;

import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.summerclouds.common.core.error.MException;
import org.summerclouds.common.core.error.RC;
import org.summerclouds.common.core.log.MLog;
import org.summerclouds.common.core.node.IProperties;
import org.summerclouds.common.core.tool.MRandom;
import org.summerclouds.common.crypt.MCrypt;
import org.summerclouds.common.crypt.cipher.CipherProvider;
import org.summerclouds.common.crypt.crypt.pem.PemBlock;
import org.summerclouds.common.crypt.crypt.pem.PemBlockModel;
import org.summerclouds.common.crypt.crypt.pem.PemKey;
import org.summerclouds.common.crypt.crypt.pem.PemKeyPair;
import org.summerclouds.common.crypt.crypt.pem.PemPair;
import org.summerclouds.common.crypt.crypt.pem.PemPriv;
import org.summerclouds.common.crypt.crypt.pem.PemPub;
import org.summerclouds.common.crypt.util.CryptUtil;

// @Component(property = "cipher=AES-JCE-01") // Default Symmetric AES - Java Cryptography Extension
public class JavaAesCipher extends MLog implements CipherProvider {

    private final String NAME = "AES-JCE-01";

    @Override
    public PemBlock encrypt(PemPub key, String content) throws MException {
        try {
            byte[] xkey = key.getBytesBlock();
            String stringEncoding = "utf-8";
            byte[] dataToSend = content.getBytes(stringEncoding);
            Cipher c = Cipher.getInstance("AES");
            SecretKeySpec k = new SecretKeySpec(xkey, "AES");
            c.init(Cipher.ENCRYPT_MODE, k);
            byte[] encryptedData = c.doFinal(dataToSend);

            PemBlockModel out = new PemBlockModel(PemBlock.BLOCK_CIPHER, encryptedData);
            CryptUtil.prepareSymmetricCipherOut(key, out, getName(), stringEncoding);

            return out;
        } catch (Throwable t) {
            throw new MException(RC.ERROR, t);
        }
    }

    @Override
    public String decrypt(PemPriv key, PemBlock encoded, String passphrase) throws MException {
        try {
            byte[] xkey = key.getBytesBlock();
            byte[] data = encoded.getBytesBlock();
            Cipher c = Cipher.getInstance("AES");
            SecretKeySpec k = new SecretKeySpec(xkey, "AES");
            c.init(Cipher.DECRYPT_MODE, k);
            byte[] enc = c.doFinal(data);

            String stringEncoding = encoded.getString(PemBlock.STRING_ENCODING, "utf-8");
            return new String(enc, stringEncoding);

        } catch (Throwable t) {
            throw new MException(RC.ERROR, t);
        }
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public PemPair createKeys(IProperties properties) throws MException {
        int length = properties.getInt(MCrypt.LENGTH, 256);
        length = length / 8 * 8;
        byte[] key = new byte[length / 8];
        for (int i = 0; i < key.length; i++) key[i] = MRandom.get().getByte();

        UUID privId = UUID.randomUUID();

        PemKey xpriv =
                new PemKey(PemBlock.BLOCK_PRIV, key, true)
                        .set(PemBlock.METHOD, getName())
                        .set(PemBlock.LENGTH, length)
                        .set(PemBlock.IDENT, privId);

        return new PemKeyPair(xpriv, xpriv);
    }
}
