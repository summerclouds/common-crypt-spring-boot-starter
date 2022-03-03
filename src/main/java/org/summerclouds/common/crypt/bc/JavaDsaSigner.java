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

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;

import org.summerclouds.common.core.error.MException;
import org.summerclouds.common.core.error.RC;
import org.summerclouds.common.core.log.MLog;
import org.summerclouds.common.core.node.IProperties;
import org.summerclouds.common.core.node.MProperties;
import org.summerclouds.common.core.tool.MRandom;
import org.summerclouds.common.core.tool.MString;
import org.summerclouds.common.crypt.MCrypt;
import org.summerclouds.common.crypt.crypt.Blowfish;
import org.summerclouds.common.crypt.crypt.pem.PemBlock;
import org.summerclouds.common.crypt.crypt.pem.PemBlockModel;
import org.summerclouds.common.crypt.crypt.pem.PemKey;
import org.summerclouds.common.crypt.crypt.pem.PemKeyPair;
import org.summerclouds.common.crypt.crypt.pem.PemPair;
import org.summerclouds.common.crypt.crypt.pem.PemPriv;
import org.summerclouds.common.crypt.crypt.pem.PemPub;
import org.summerclouds.common.crypt.signer.SignerProvider;
import org.summerclouds.common.crypt.util.CryptUtil;

// http://bounce-com.s3.amazonaws.com/b93ede49-06e1-44dc-9caf-8ca7fe04896f/e084edee-e787-42b5-8b18-559fc8a09bad/solving-java-application-errors-in-production.original.pdf?x-amz-security-token=FQoDYXdzEL3%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaDKLUAR0ROzxuWIDf9yK3AwJ7WvPa5hYMUZW0crQu1EUfwn9lRqH1Cg8rJrrTJIU6Up00b%2Fnvo%2BeXVpmJT%2BGClrXs9BErDO1Q%2BJM7dqzwZFetvxkilYZ7LIFg8J0nOiA0mhKbkTAKpELzhxqzM3fq7JHbyQTSpgz5mH1Q178DB41UuwiqrVxSkrih5SimDgKt1WhXwTD3nY0kbCOio2WTtTmBbfx%2F6p47uOHJpo%2BMqpeVDzahNisFbyKxYnWTMXiC8JNXptFZEeWkV%2F5zchoXT3kDgZkqF%2FW4pE89%2FJgeP5bUVcH0Wkrnf2D2iHLvlehYTs060%2FC9Q2DwTfhwl6gDiQzrDVlDUbEL80pvOu1k8QQE3aEgmOyyhIa92iIO%2FbfWYG3WX1nuhi%2B9wbpTfgMc%2FHnZ7eq0O%2F7JwVubFYUxvtUizsolPfJ7E%2Bv3Hnj3zeahWnU0XglEOg5QequqWisq3pN6PUKzaAQaAW40r0nxMSi8kxk%2F6e527MRHEYdWyLv2GyYY%2F8vhpA3aINmemq%2B8Ndnu9eVJ6sMCqH7v0kZ5X5XGtb5Xz%2FWfEsz9HqvJBopMSqBYWqGQ0JUHU7G6DoWd86ip6A9vBYAoqsTMxAU%3D&AWSAccessKeyId=ASIAJUR7I5ODZ6DWSGEA&Expires=1486041245&Signature=ZGCLe2NXvRQyv5CTVW43tFQSbFQ%3D

//@Component(property = "signer=DSA-JCE-01") // SUNDSA
public class JavaDsaSigner extends MLog implements SignerProvider {

    private static String NAME = "DSA-JCE-01";

    @Override
    public PemBlock sign(PemPriv key, String text, String passphrase) throws MException {
        try {
            byte[] encKey = key.getBytesBlock();
            if (MString.isSet(passphrase)) encKey = Blowfish.decrypt(encKey, passphrase);
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(encKey);
            KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
            PrivateKey privKey = keyFactory.generatePrivate(privKeySpec);

            Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
            dsa.initSign(privKey);
            byte[] buffer = text.getBytes();
            dsa.update(buffer, 0, buffer.length);

            byte[] realSig = dsa.sign();

            PemBlockModel out = new PemBlockModel(PemBlock.BLOCK_SIGN, realSig);
            CryptUtil.prepareSignOut(key, out, getName());

            return out;
        } catch (Exception e) {
            throw new MException(RC.ERROR, e);
        }
    }

    @Override
    public boolean validate(PemPub key, String text, PemBlock sign) throws MException {
        try {
            byte[] encKey = key.getBytesBlock();
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
            KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
            PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

            Signature sig = Signature.getInstance("SHA1withDSA", "SUN");
            sig.initVerify(pubKey);

            byte[] buffer = text.getBytes();
            sig.update(buffer, 0, buffer.length);

            byte[] sigToVerify = sign.getBytesBlock();
            return sig.verify(sigToVerify);

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
            int len = properties.getInt(MCrypt.LENGTH, 1024);
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
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
