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
package org.summerclouds.common.crypt.signer;

import org.summerclouds.common.core.error.MException;
import org.summerclouds.common.core.node.IProperties;
import org.summerclouds.common.core.util.SecureString;
import org.summerclouds.common.crypt.crypt.pem.PemBlock;
import org.summerclouds.common.crypt.crypt.pem.PemPair;
import org.summerclouds.common.crypt.crypt.pem.PemPriv;
import org.summerclouds.common.crypt.crypt.pem.PemPub;

public interface SignerProvider {

    /**
     * Create a sign of the full text.
     *
     * @param key
     * @param text
     * @param passphrase
     * @return a block with the sign content
     * @throws MException
     */
    PemBlock sign(PemPriv key, String text, String passphrase) throws MException;

    default PemBlock sign(PemPriv key, String text, SecureString passphrase) throws MException {
        return sign(key, text, passphrase == null ? null : passphrase.value());
    }

    default PemBlock sign(PemPriv key, String text) throws MException {
        return sign(key, text, (String) null);
    }

    boolean validate(PemPub key, String text, PemBlock sign) throws MException;

    String getName();

    PemPair createKeys(IProperties properties) throws MException;
}
