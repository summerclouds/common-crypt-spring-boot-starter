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
package org.summerclouds.common.crypt;

import org.summerclouds.common.core.error.MException;
import org.summerclouds.common.core.util.SecureString;
import org.summerclouds.common.crypt.crypt.pem.PemBlock;
import org.summerclouds.common.crypt.crypt.pem.PemPriv;
import org.summerclouds.common.crypt.crypt.pem.PemPub;

public interface PemProcessContext {

    void errorKeyNotFound(PemBlock block) throws CryptException;

    PemPriv getPrivateKey(String privId) throws MException;

    String getPrivateIdForPublicKeyId(String pubId) throws CryptException;

    SecureString getPassphrase(String privId, PemBlock block) throws CryptException;

    void foundSecret(PemBlock block, SecureString sec);

    void foundPublicKey(PemBlock block);

    void foundPrivateKey(PemBlock block);

    PemPub getPublicKey(String keyId);

    void foundHash(PemBlock block);

    void foundValidated(PemBlock block);
}
