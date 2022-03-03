/**
 * Copyright (C) 2002 Mike Hummel (mh@mhus.de)
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

import org.summerclouds.common.core.crypt.KeyEntry;
import org.summerclouds.common.core.error.NotSupportedException;
import org.summerclouds.common.core.parser.ParseException;
import org.summerclouds.common.core.tool.MKeychain;
import org.summerclouds.common.crypt.MCrypt;
import org.summerclouds.common.crypt.crypt.AsyncKey;
import org.summerclouds.common.crypt.crypt.pem.PemPriv;
import org.summerclouds.common.crypt.crypt.pem.PemPub;
import org.summerclouds.common.crypt.crypt.pem.PemUtil;

public class DefaultVaultMutator implements KeyMutator {

    /**
     * Try to adapt the entry to the given class or interface.
     *
     * @param entry
     * @param ifc
     * @return The requested interface or class.
     * @throws NotSupportedException Thrown if the entry can't be adapted to the interface.
     * @throws ParseException
     */
    @Override
    @SuppressWarnings("unchecked")
    public <T> T adaptTo(KeyEntry entry, Class<? extends T> ifc)
            throws ParseException, NotSupportedException {
        if (entry.getType() != null) {
            try {
                if (ifc == AsyncKey.class
                        && MKeychain.TYPE_RSA_PRIVATE_KEY.equals(entry.getType())) {
                    return (T) MCrypt.loadPrivateRsaKey(entry.getValue().value());
                }
                if (ifc == AsyncKey.class
                        && MKeychain.TYPE_RSA_PUBLIC_KEY.equals(entry.getType())) {
                    return (T) MCrypt.loadPrivateRsaKey(entry.getValue().value());
                }
                if (ifc == PemPriv.class
                        && entry.getType().endsWith(MKeychain.SUFFIX_CIPHER_PRIVATE_KEY)) {
                    return (T) PemUtil.cipherPrivFromString(entry.getValue().value());
                }
                if (ifc == PemPub.class
                        && entry.getType().endsWith(MKeychain.SUFFIX_CIPHER_PUBLIC_KEY)) {
                    return (T) PemUtil.cipherPubFromString(entry.getValue().value());
                }
                if (ifc == PemPriv.class
                        && entry.getType().endsWith(MKeychain.SUFFIX_SIGN_PRIVATE_KEY)) {
                    return (T) PemUtil.signPrivFromString(entry.getValue().value());
                }
                if (ifc == PemPub.class
                        && entry.getType().endsWith(MKeychain.SUFFIX_SIGN_PUBLIC_KEY)) {
                    return (T) PemUtil.signPubFromString(entry.getValue().value());
                }
            } catch (Exception e) {
                throw new ParseException(e);
            }
        }
        throw new NotSupportedException(entry, ifc);
    }
}
