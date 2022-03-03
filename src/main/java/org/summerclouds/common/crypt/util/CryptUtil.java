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

import org.summerclouds.common.core.error.MException;
import org.summerclouds.common.crypt.crypt.pem.PemBlock;
import org.summerclouds.common.crypt.crypt.pem.PemBlockModel;
import org.summerclouds.common.crypt.crypt.pem.PemPriv;
import org.summerclouds.common.crypt.crypt.pem.PemPub;

public class CryptUtil {

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
