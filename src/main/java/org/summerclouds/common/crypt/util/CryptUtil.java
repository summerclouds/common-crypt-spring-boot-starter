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

import java.util.Date;

import org.summerclouds.common.core.M;
import org.summerclouds.common.core.error.MException;
import org.summerclouds.common.crypt.cipher.CipherProvider;
import org.summerclouds.common.crypt.crypt.pem.PemBlock;
import org.summerclouds.common.crypt.crypt.pem.PemBlockModel;
import org.summerclouds.common.crypt.crypt.pem.PemKey;
import org.summerclouds.common.crypt.crypt.pem.PemPriv;
import org.summerclouds.common.crypt.crypt.pem.PemPub;
import org.summerclouds.common.crypt.crypt.pem.PemUtil;
import org.summerclouds.common.crypt.signer.SignerProvider;

import de.mhus.crypt.api.CryptApi;

public class CryptUtil {

    public static CipherProvider getCipher(String key) throws MException {
        CryptApi api = M.l(CryptApi.class);
        PemBlock pem = PemUtil.parse(key);
        // check for cipher key ??
        String method = pem.getString(PemBlock.METHOD);
        // legacy method mappings??
        return api.getCipher(method);
    }

    public static SignerProvider getSigner(String key) throws MException {
        CryptApi api = M.l(CryptApi.class);
        PemBlock pem = PemUtil.parse(key);
        // check for signer key ??
        String method = pem.getString(PemBlock.METHOD);
        // legacy method mappings??
        return api.getSigner(method);
    }

    public static String encrypt(String publicKey, String content) throws MException {
        CryptApi api = M.l(CryptApi.class);
        PemKey key = PemUtil.toKey(publicKey);
        // check for cipher key ??
        String method = key.getString(PemBlock.METHOD);
        // legacy method mappings??
        CipherProvider cipher = api.getCipher(method);
        PemBlock res = cipher.encrypt(key, content);
        return res.toString();
    }

    public static String decrypt(String privateKey, String passphrase, String content)
            throws MException {
        CryptApi api = M.l(CryptApi.class);
        PemKey key = PemUtil.toKey(privateKey);
        PemBlock contentPem = PemUtil.parse(content);
        // check for cipher key ??
        String method = key.getString(PemBlock.METHOD);
        // legacy method mappings??
        CipherProvider cipher = api.getCipher(method);
        String res = cipher.decrypt(key, contentPem, passphrase);
        return res;
    }

    public static String sign(String privateKey, String passphrase, String content)
            throws MException {
        CryptApi api = M.l(CryptApi.class);
        PemKey key = PemUtil.toKey(privateKey);
        // check for cipher key ??
        String method = key.getString(PemBlock.METHOD);
        // legacy method mappings??
        SignerProvider signer = api.getSigner(method);
        PemBlock res = signer.sign(key, content, passphrase);
        return res.toString();
    }

    public static boolean validate(String publicKey, String signature, String content)
            throws MException {
        CryptApi api = M.l(CryptApi.class);
        PemKey key = PemUtil.toKey(publicKey);
        PemBlock signPem = PemUtil.parse(signature);
        // check for cipher key ??
        String method = key.getString(PemBlock.METHOD);
        // legacy method mappings??
        SignerProvider signer = api.getSigner(method);
        boolean res = signer.validate(key, content, signPem);
        return res;
    }

    public static void prepareSignOut(PemPriv key, PemBlockModel out, String name) {
        out.set(PemBlock.METHOD, name);
        if (key.isProperty(PemBlock.IDENT))
            out.set(PemBlock.PRIV_ID, key.getProperty(PemBlock.IDENT));
        if (key.isProperty(PemBlock.PUB_ID))
            out.set(PemBlock.PUB_ID, key.getProperty(PemBlock.PUB_ID));
        out.set(PemBlock.CREATED, new Date());
    }

    public static void prepareCipherOut(
            PemPub key, PemBlockModel out, String name, String stringEncoding) throws MException {
        out.set(PemBlock.METHOD, name);
        if (stringEncoding != null) out.set(PemBlock.STRING_ENCODING, stringEncoding);
        if (key.isProperty(PemBlock.IDENT)) out.set(PemBlock.PUB_ID, key.getString(PemBlock.IDENT));
        if (key.isProperty(PemBlock.PRIV_ID))
            out.set(PemBlock.PRIV_ID, key.getString(PemBlock.PRIV_ID));
        out.set(PemBlock.CREATED, new Date());
    }

    public static void prepareSymmetricCipherOut(
            PemPub key, PemBlockModel out, String name, String stringEncoding) throws MException {
        out.set(PemBlock.METHOD, name);
        out.set(PemBlock.SYMMETRIC, true);
        if (stringEncoding != null) out.set(PemBlock.STRING_ENCODING, stringEncoding);
        if (key.isProperty(PemBlock.IDENT)) out.set(PemBlock.KEY_ID, key.getString(PemBlock.IDENT));
        out.set(PemBlock.CREATED, new Date());
    }
}
