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
package org.summerclouds.common.crypt.bc;

import java.io.ByteArrayOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;

import javax.crypto.Cipher;

import org.summerclouds.common.core.error.MException;
import org.summerclouds.common.core.error.RC;
import org.summerclouds.common.core.log.MLog;
import org.summerclouds.common.core.node.IProperties;
import org.summerclouds.common.core.node.MProperties;
import org.summerclouds.common.core.tool.MRandom;
import org.summerclouds.common.core.tool.MString;
import org.summerclouds.common.crypt.cipher.CipherProvider;
import org.summerclouds.common.crypt.crypt.Blowfish;
import org.summerclouds.common.crypt.crypt.MCrypt;
import org.summerclouds.common.crypt.crypt.pem.PemBlock;
import org.summerclouds.common.crypt.crypt.pem.PemBlockModel;
import org.summerclouds.common.crypt.crypt.pem.PemKey;
import org.summerclouds.common.crypt.crypt.pem.PemKeyPair;
import org.summerclouds.common.crypt.crypt.pem.PemPair;
import org.summerclouds.common.crypt.crypt.pem.PemPriv;
import org.summerclouds.common.crypt.crypt.pem.PemPub;
import org.summerclouds.common.crypt.util.CryptUtil;

//@Component(property = "cipher=RSA-JCE-01") // Default RSA - Java Cryptography Extension
public class JavaRsaCipher extends MLog implements CipherProvider {

    private final String NAME = "RSA-JCE-01";

    private static final String TRANSFORMATION_RSA = "RSA/ECB/PKCS1Padding";
    private static final String ALGORITHM_RSA = "RSA";

    @Override
    public PemBlock encrypt(PemPub key, String content) throws MException {
        try {
            byte[] encKey = key.getBytesBlock();
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_RSA);
            PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION_RSA);
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);

            String stringEncoding = "utf-8";
            byte[] b = content.getBytes(stringEncoding);
            ByteArrayOutputStream os = new ByteArrayOutputStream();

            int length = key.getInt(PemBlock.LENGTH, 1024);
            int blockSize = length == 512 ? 53 : 117;

            int off = 0;
            while (off < b.length) {
                int len = Math.min(blockSize, b.length - off);
                byte[] cipherData = cipher.doFinal(b, off, len);
                os.write(cipherData);
                off = off + len;
            }

            PemBlockModel out = new PemBlockModel(PemBlock.BLOCK_CIPHER, os.toByteArray());
            CryptUtil.prepareCipherOut(key, out, getName(), stringEncoding);

            return out;

        } catch (Throwable t) {
            throw new MException(RC.ERROR, t);
        }
    }

    @Override
    public String decrypt(PemPriv key, PemBlock encoded, String passphrase) throws MException {
        try {
            byte[] encKey = key.getBytesBlock();
            if (MString.isSet(passphrase)) encKey = Blowfish.decrypt(encKey, passphrase);
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(encKey);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_RSA);
            PrivateKey privKey = keyFactory.generatePrivate(privKeySpec);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION_RSA);
            cipher.init(Cipher.DECRYPT_MODE, privKey);

            int length = key.getInt(PemBlock.LENGTH, 1024);
            int blockSize = Math.max(length / 1024 * 128, 64);

            byte[] b = encoded.getBytesBlock();
            ByteArrayOutputStream os = new ByteArrayOutputStream();

            int off = 0;
            while (off < b.length) {
                int len = Math.min(blockSize, b.length - off);
                byte[] realData = cipher.doFinal(b, off, len);
                os.write(realData);
                off = off + len;
            }

            String stringEncoding = encoded.getString(PemBlock.STRING_ENCODING, "utf-8");
            return new String(os.toByteArray(), stringEncoding);

        } catch (Exception e) {
            throw new MException(RC.ERROR, e);
        }
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public PemPair createKeys(IProperties properties) throws MException {
        try {
            if (properties == null) properties = new MProperties();
            int len = properties.getInt(MCrypt.LENGTH, 1024); // 8192
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(len, MRandom.get().getSecureRandom());

            KeyPair pair = keyGen.generateKeyPair();
            PrivateKey priv = pair.getPrivate();
            PublicKey pub = pair.getPublic();

            UUID privId = UUID.randomUUID();
            UUID pubId = UUID.randomUUID();

            byte[] privBytes = priv.getEncoded();
            String passphrase = properties.getString(MCrypt.PASSPHRASE, null);
            if (MString.isSet(passphrase)) privBytes = Blowfish.encrypt(privBytes, passphrase);

            PemKey xpub =
                    new PemKey(PemBlock.BLOCK_PUB, pub.getEncoded(), false)
                            .set(PemBlock.METHOD, getName())
                            .set(PemBlock.LENGTH, len)
                            .set(PemBlock.FORMAT, pub.getFormat())
                            .set(PemBlock.IDENT, pubId)
                            .set(PemBlock.PRIV_ID, privId);
            PemKey xpriv =
                    new PemKey(PemBlock.BLOCK_PRIV, privBytes, true)
                            .set(PemBlock.METHOD, getName())
                            .set(PemBlock.LENGTH, len)
                            .set(PemBlock.FORMAT, priv.getFormat())
                            .set(PemBlock.IDENT, privId)
                            .set(PemBlock.PUB_ID, pubId);
            if (MString.isSet(passphrase)) xpriv.set(PemBlock.ENCRYPTED, PemBlock.ENC_BLOWFISH);

            privBytes = null;
            return new PemKeyPair(xpriv, xpub);

        } catch (Exception e) {
            throw new MException(RC.ERROR, e);
        }
    }
}
