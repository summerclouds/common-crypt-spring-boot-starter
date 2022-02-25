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
import java.security.spec.ECGenParameterSpec;
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
import org.summerclouds.common.crypt.crypt.Blowfish;
import org.summerclouds.common.crypt.crypt.MCrypt;
import org.summerclouds.common.crypt.crypt.pem.PemBlock;
import org.summerclouds.common.crypt.crypt.pem.PemBlockModel;
import org.summerclouds.common.crypt.crypt.pem.PemKey;
import org.summerclouds.common.crypt.crypt.pem.PemKeyPair;
import org.summerclouds.common.crypt.crypt.pem.PemPair;
import org.summerclouds.common.crypt.crypt.pem.PemPriv;
import org.summerclouds.common.crypt.crypt.pem.PemPub;
import org.summerclouds.common.crypt.signer.SignerProvider;
import org.summerclouds.common.crypt.util.CryptUtil;

// http://bouncycastle.org/wiki/display/JA1/Elliptic+Curve+Key+Pair+Generation+and+Key+Factories

//@Component(property = "signer=ECC-BC-01")
public class EccSigner extends MLog implements SignerProvider {

    private static String NAME = "ECC-BC-01";

    private static final String PROVIDER = "BC";
    private static final String TRANSFORMATION_ECC = "SHA512WITHECDSA";
    private static final String ALGORITHM_ECC = "ECDSA";

//    @Activate
//    public void doActivate(ComponentContext ctx) {
//        MBouncy.init();
//    }

    @Override
    public PemBlock sign(PemPriv key, String text, String passphrase) throws MException {
        try {
            byte[] encKey = key.getBytesBlock();
            if (MString.isSet(passphrase)) encKey = Blowfish.decrypt(encKey, passphrase);
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(encKey);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_ECC, PROVIDER);
            PrivateKey privKey = keyFactory.generatePrivate(privKeySpec);

            Signature sig = Signature.getInstance(TRANSFORMATION_ECC, PROVIDER);
            sig.initSign(privKey);
            byte[] buffer = text.getBytes();
            sig.update(buffer, 0, buffer.length);

            byte[] realSig = sig.sign();

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
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_ECC, PROVIDER);
            PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

            Signature sig = Signature.getInstance(TRANSFORMATION_ECC, PROVIDER);
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
            //			EllipticCurve curve = new EllipticCurve(
            //		            new ECFieldFp(new
            // BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839")), // q
            //		            new
            // BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
            //		            new
            // BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b
            //			ECParameterSpec ecSpec = new ECParameterSpec(
            //			            curve,
            //			            ECPointUtil.decodePoint(curve,
            // Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
            //			            new
            // BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307"), // n
            //			            1); // h
            //			KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");
            //			g.initialize(ecSpec, random.getSecureRandom());
            //			KeyPair pair = g.generateKeyPair();
            if (properties == null) properties = new MProperties();

            String stdName = properties.getString("stdName", "prime192v1");
            ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(stdName);
            KeyPairGenerator g = KeyPairGenerator.getInstance(ALGORITHM_ECC, PROVIDER);
            g.initialize(ecGenSpec, MRandom.get().getSecureRandom());
            KeyPair pair = g.generateKeyPair();

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
                            .set("StdName", stdName)
                            .set(PemBlock.FORMAT, pub.getFormat())
                            .set(PemBlock.IDENT, pubId)
                            .set(PemBlock.PRIV_ID, privId);
            PemKey xpriv =
                    new PemKey(PemBlock.BLOCK_PRIV, privBytes, true)
                            .set(PemBlock.METHOD, getName())
                            .set("StdName", stdName)
                            .set(PemBlock.FORMAT, priv.getFormat())
                            .set(PemBlock.IDENT, privId)
                            .set(PemBlock.PUB_ID, pubId);

            if (MString.isSet(passphrase)) xpriv.set(PemBlock.ENCRYPTED, PemBlock.ENC_BLOWFISH);
            privBytes = null;
            return new PemKeyPair(xpriv, xpub);

        } catch (Throwable t) {
            throw new MException(RC.ERROR, t);
        }
    }
}

/*
 *
The following ECDSA curves are currently supported by the Bouncy Castle APIs:
F p
X9.62
Curve	Size (in bits)
prime192v1
192
prime192v2	192
prime192v3	192
prime239v1	239
prime239v2	239
prime239v3	239
prime256v1	256
SEC
Curve
Size (in bits)
secp192k1	192
secp192r1	192
secp224k1	224
secp224r1	224
secp256k1	256
secp256r1	256
secp384r1	384
secp521r1	521
NIST (aliases for SEC curves)
Curve
Size (in bits)
P-224	224
P-256	256
P-384	384
P-521	521
F 2m
X9.62
Curve
Size (in bits)
c2pnb163v1	163
c2pnb163v2	163
c2pnb163v3	163
c2pnb176w1	176
c2tnb191v1	191
c2tnb191v2
191
c2tnb191v3	191
c2pnb208w1	208
c2tnb239v1	239
c2tnb239v2	239
c2tnb239v3	239
c2pnb272w1	272
c2pnb304w1	304
c2tnb359v1	359
c2pnb368w1	368
c2tnb431r1	431
SEC
Curve
Size (in bits)
sect163k1	163
sect163r1	163
sect163r2	163
sect193r1	193
sect193r2	193
sect233k1	233
sect233r1	233
sect239k1	239
sect283k1	283
sect283r1	283
sect409k1	409
sect409r1	409
sect571k1	571
sect571r1	571
NIST (aliases for SEC curves)
Curve
Size (in bits)
B-163
163
B-233	233
B-283	283
B-409	409
B-571	571
Teletrust
Curve
Size (in bits)
brainpoolp160r1	160
brainpoolp160t1	160
brainpoolp192r1	192
brainpoolp192t1	192
brainpoolp224r1	224
brainpoolp224t1	224
brainpoolp256r1	256
brainpoolp256t1	256
brainpoolp320r1	320
brainpoolp320t1	320
brainpoolp384r1	384
brainpoolp384t1	384
brainpoolp512r1	512
brainpoolp512t1	512
Supported ECGOST (GOST3410-2001) Curves
The following ECGOST curves are currently supported by the Bouncy Castle APIs:
Curve
GostR3410-2001-CryptoPro-A
GostR3410-2001-CryptoPro-XchB
GostR3410-2001-CryptoPro-XchA
GostR3410-2001-CryptoPro-C
GostR3410-2001-CryptoPro-B

 *
 */
