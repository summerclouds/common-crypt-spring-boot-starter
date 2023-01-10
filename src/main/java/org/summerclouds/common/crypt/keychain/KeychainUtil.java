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
package org.summerclouds.common.crypt.keychain;

import org.summerclouds.common.core.M;
import org.summerclouds.common.core.crypt.KeyEntry;
import org.summerclouds.common.core.error.NotSupportedException;
import org.summerclouds.common.core.parser.ParseException;
import org.summerclouds.common.core.tool.MKeychain;

public class KeychainUtil {

    /**
     * Try to adapt the entry to the given class or interface.
     *
     * @param entry
     * @param ifc
     * @return The requested interface or class.
     * @throws NotSupportedException Thrown if the entry can't be adapted to the interface.
     * @throws ParseException
     */
    public static <T> T adaptTo(KeyEntry entry, Class<? extends T> ifc)
            throws ParseException, NotSupportedException {
        // delegate to service
        return M.l(KeyMutator.class).adaptTo(entry, ifc);
    }

    public static String getType(String content) {

        if (content == null) return MKeychain.TYPE_TEXT;

        // only analyse the first block in content
        int pos = content.indexOf("-----END ");
        if (pos < 0) return MKeychain.TYPE_TEXT;
        content = content.substring(0, pos);

        if (content.contains("-----BEGIN RSA PRIVATE KEY-----"))
            return MKeychain.TYPE_RSA_PRIVATE_KEY;
        if (content.contains("-----BEGIN RSA PUBLIC KEY-----"))
            return MKeychain.TYPE_RSA_PUBLIC_KEY;
        if (content.contains("-----BEGIN DSA PRIVATE KEY-----"))
            return MKeychain.TYPE_DSA_PRIVATE_KEY;
        if (content.contains("-----BEGIN DSA PUBLIC KEY-----"))
            return MKeychain.TYPE_DSA_PUBLIC_KEY;
        if (content.contains("-----BEGIN ECC PRIVATE KEY-----"))
            return MKeychain.TYPE_ECC_PRIVATE_KEY;
        if (content.contains("-----BEGIN ECC PUBLIC KEY-----"))
            return MKeychain.TYPE_ECC_PUBLIC_KEY;
        if (content.contains("-----BEGIN PRIVATE KEY-----")) {
            if (content.contains("Method: AES")) return MKeychain.TYPE_AES_PRIVATE_KEY;
            if (content.contains("Method: RSA")) return MKeychain.TYPE_RSA_PRIVATE_KEY;
            if (content.contains("Method: ECC")) return MKeychain.TYPE_ECC_PRIVATE_KEY;
            if (content.contains("Method: DSA")) return MKeychain.TYPE_DSA_PRIVATE_KEY;
        }
        if (content.contains("-----BEGIN PUBLIC KEY-----")) {
            if (content.contains("Method: AES")) return MKeychain.TYPE_AES_PUBLIC_KEY;
            if (content.contains("Method: RSA")) return MKeychain.TYPE_RSA_PUBLIC_KEY;
            if (content.contains("Method: ECC")) return MKeychain.TYPE_ECC_PUBLIC_KEY;
            if (content.contains("Method: DSA")) return MKeychain.TYPE_DSA_PUBLIC_KEY;
        }
        if (content.contains("-----BEGIN CIPHER-----")) return MKeychain.TYPE_CIPHER;
        if (content.contains("-----BEGIN SIGNATURE-----")) return MKeychain.TYPE_SIGNATURE;
        else return MKeychain.TYPE_TEXT;
    }

    /**
     * Try to adapt the source to the given class or interface.
     *
     * @param source
     * @param ifc
     * @return The requested interface or class.
     * @throws NotSupportedException Thrown if the source can't be adapted to the interface.
     */
    //	@SuppressWarnings("unchecked")
    //	public static <T> T adaptTo(VaultSource source, Class<? extends T> ifc) throws
    // NotSupportedException {
    //		if (ifc.isInstance(source)) return (T) source;
    //		throw new NotSupportedException(source,ifc);
    //	}

}
