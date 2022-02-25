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
package org.summerclouds.common.crypt.crypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.LinkedList;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.summerclouds.common.core.cfg.CfgInt;
import org.summerclouds.common.core.cfg.CfgLong;
import org.summerclouds.common.core.tool.MCast;
import org.summerclouds.common.core.tool.MPeriod;
import org.summerclouds.common.core.tool.MRandom;
import org.summerclouds.common.core.tool.MString;
import org.summerclouds.common.core.tool.MThread;
import org.summerclouds.common.crypt.crypt.pem.PemBlock;
import org.summerclouds.common.crypt.crypt.pem.PemBlockModel;
import org.summerclouds.common.crypt.crypt.pem.PemUtil;

/**
 * This utility uses explicit bouncy castle methods for cryptography. It depends on BC but not JCE.
 * For some compatibility reasons it makes sense to use BC instead of JCE (e.g. open jdk on not
 * common environments / hardware JCE is not available).
 *
 * @author mikehummel
 */
public class MBouncy {

    public enum RSA_KEY_SIZE {
        B1024,
        B2048,
        B4096;

        private int bits = MCast.toint(name().substring(1), 1024);

        public int getBits() {
            return bits;
        }

        public int getBlockSize() {
            return Math.max(getBits() / 1024 * 128, 64);
        }
    }

    public enum ECC_SPEC {
        PRIME192V1,
        PRIME192V2,
        PRIME192V3,
        PRIME239V1,
        PRIME239V2,
        PRIME239V3,
        PRIME256V1,
        SECP192K1,
        SECP192R1,
        SECP244K1,
        SECP244R1,
        SECP256K1,
        SECP256R1,
        SECP384R1,
        SECP521R1
    };

    public static void init() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
            Security.addProvider(new BouncyCastleProvider());
    }

    protected static final String ALGORITHM_RSA = "RSA";
    protected static final String PROVIDER = "BC";
    protected static final String TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    protected static final String ALGORITHM_AES = "AES";
    private static final Charset STRING_ENCODING = MString.CHARSET_CHARSET_UTF_8;
    public static final RSA_KEY_SIZE RSA_KEY_SIZE_DEFAULT = RSA_KEY_SIZE.B1024;
    private static final String TRANSFORMATION_ECC = "SHA512WITHECDSA";
    private static final String ALGORITHM_ECC = "ECDSA";

    private static LinkedList<KeyPair> keyPool = new LinkedList<>();
    private static long keyPoolUpdate = 0;
    private static CfgLong CFG_POOL_UPDATE_TIME =
            new CfgLong(MBouncy.class, "poolUpdateTime", MPeriod.MINUTE_IN_MILLISECONDS * 10);
    private static CfgInt CFG_POOL_SIZE = new CfgInt(MBouncy.class, "poolSize", 10);

    /**
     * Generate a RSA key pair with 1024 bits.
     *
     * @param size
     * @return The key pair
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    // With help from https://github.com/ingoclaro/crypt-examples/tree/master/java/src
    public static KeyPair generateRsaKey(RSA_KEY_SIZE size)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        init();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM_RSA, PROVIDER);
        keyGen.initialize(size.getBits());
        KeyPair key = keyGen.generateKeyPair();
        return key;
    }

    /**
     * Transform a string encoded public key to a public key object.
     *
     * @param key Public Key as string
     * @return Public Key as object
     */
    // http://www.javased.com/index.php?api=java.security.PrivateKey
    public static PublicKey getPublicKey(String key) {
        try {
            init();
            byte[] encodedKey = decodeBase64(key);
            X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(encodedKey);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_RSA, PROVIDER);
            return keyFactory.generatePublic(encodedKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Transforms a string encoded private key into a private key object
     *
     * @param key Private Key as string
     * @return Private Key as object
     */
    public static PrivateKey getPrivateKey(String key) {
        try {
            init();
            byte[] encodedKey = decodeBase64(key);
            PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(encodedKey);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_RSA, PROVIDER);
            return keyFactory.generatePrivate(encodedKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Returns the public key of a key pair as string
     *
     * @param key
     * @return Public Key as string
     */
    public static String getPublicKey(KeyPair key) {
        return encodeBase64(new X509EncodedKeySpec(key.getPublic().getEncoded()).getEncoded());
    }

    /**
     * Returns the private key of a key pair as string
     *
     * @param key
     * @return Private Key as string
     */
    public static String getPrivateKey(KeyPair key) {
        return encodeBase64(new PKCS8EncodedKeySpec(key.getPrivate().getEncoded()).getEncoded());
    }

    public static PemBlock getPrivatePem(KeyPair pair) {
        PrivateKey key = pair.getPrivate();
        return getPrivatePem(key);
    }

    public static PemBlock getPrivatePem(PrivateKey key) {
        PemBlockModel pem = new PemBlockModel(PemBlock.BLOCK_PRIV);
        pem.setString(PemBlock.METHOD, key.getAlgorithm());
        pem.setString(PemBlock.FORMAT, key.getFormat());
        pem.setBlock(key.getEncoded());
        return pem;
    }

    public static PemBlock getPublicPem(KeyPair pair) {
        PublicKey key = pair.getPublic();
        return getPublicPem(key);
    }

    public static PemBlock getPublicPem(PublicKey key) {
        PemBlockModel pem = new PemBlockModel(PemBlock.BLOCK_PUB);
        pem.setString(PemBlock.METHOD, key.getAlgorithm());
        pem.setString(PemBlock.FORMAT, key.getFormat());
        pem.setBlock(key.getEncoded());
        return pem;
    }

    /**
     * Encrypt one block with maximal 117 bytes (block size for 1024). Optimized for one block step.
     *
     * @param text
     * @param key
     * @return The encrypted block (128 bytes for 1024 bits, 256 bytes for 2048 bits ...)
     * @throws Exception
     */
    public static byte[] encryptRsa117(byte[] text, PublicKey key) throws Exception {
        init();
        byte[] cipherText = null;
        //
        // get an RSA cipher object and print the provider
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, PROVIDER);

        // encrypt the plaintext using the public key
        cipher.init(Cipher.ENCRYPT_MODE, key);
        cipherText = cipher.doFinal(text);
        return cipherText;
    }

    /**
     * Encrypt a unlimited amount of bytes with rsa.
     *
     * @param text
     * @param key
     * @return encrypted bytes
     * @throws Exception
     */
    public static byte[] encryptRsa(byte[] text, PublicKey key) throws Exception {
        init();
        // get an RSA cipher object and print the provider
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, PROVIDER);
        // encrypt the plaintext using the public key
        cipher.init(Cipher.ENCRYPT_MODE, key);
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        int start = 0;
        while (true) {
            int len = text.length - start;
            if (len <= 117) {
                byte[] out = cipher.doFinal(text, start, len);
                os.write(out);
                break;
            } else {
                byte[] out = cipher.doFinal(text, start, 117);
                os.write(out);
            }
            start = start + 117;
        }
        return os.toByteArray();
    }

    /**
     * Decrypt an encrypted block.
     *
     * @param text
     * @param key
     * @param size
     * @return decrypted data
     * @throws Exception
     */
    public static byte[] decryptRsa(byte[] text, PrivateKey key, RSA_KEY_SIZE size)
            throws Exception {
        init();
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, PROVIDER);
        cipher.init(Cipher.DECRYPT_MODE, key);

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        int blockSize = size.getBlockSize();
        int start = 0;
        while (true) {
            int len = text.length - start;
            if (len > blockSize) len = blockSize;
            byte[] out = cipher.doFinal(text, start, len);
            os.write(out);
            if (start + len >= text.length) {
                break;
            }
            start = start + len;
        }
        return os.toByteArray();
    }

    /**
     * Encrypt a single block with max 117 bytes as base64 string. Optimized for one block
     * encryption. The text will be encoded with UTF8.
     *
     * @param text UTF8 Text
     * @param key
     * @return encrypted string
     * @throws Exception
     */
    public static String encryptRsa117(String text, PublicKey key) throws Exception {
        String encryptedText;
        byte[] cipherText = encryptRsa(text.getBytes(STRING_ENCODING), key);
        encryptedText = encodeBase64(cipherText);
        return encryptedText;
    }

    /**
     * Decrypt a single rsa block (128 bytes for 1024 bits, 256 for 2048 bits ...) with a result of
     * maximal 117 bytes. Optimized for a single block step.
     *
     * @param text
     * @param key
     * @return decrypted string
     * @throws Exception
     */
    public static byte[] decryptRsa117(byte[] text, PrivateKey key) throws Exception {
        init();
        byte[] dectyptedText = null;
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, PROVIDER);
        cipher.init(Cipher.DECRYPT_MODE, key);
        dectyptedText = cipher.doFinal(text);
        return dectyptedText;
    }

    /**
     * Decrypt a single base64 encrypted byte block. The text will decoded with UTF8.
     *
     * @param text
     * @param key
     * @return decrypted string
     * @throws Exception
     */
    public static String decryptRsa117(String text, PrivateKey key) throws Exception {
        init();
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, PROVIDER);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] enc = decodeBase64(text);
        byte[] dectyptedText = cipher.doFinal(enc);
        // byte[] dectyptedText = decryptRsa(decodeBase64(text),key, size);
        String result = new String(dectyptedText, STRING_ENCODING);
        return result;
    }

    /**
     * encode bytes with base64 algorithm.
     *
     * @param bytes
     * @return Base64 encoded string
     */
    public static String encodeBase64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * Decode Base64 encoded string to bytes
     *
     * @param text
     * @return original bytes
     */
    public static byte[] decodeBase64(String text) {
        return Base64.getDecoder().decode(text);
    }

    /**
     * Create a array of 'size' with random content.
     *
     * @param size
     * @return random content
     */
    public static byte[] createRandom(int size) {
        byte[] out = new byte[size];
        for (int i = 0; i < out.length; i++) out[i] = MRandom.getByte();
        return out;
    }

    /**
     * Encrypt the data using symmetric AES.
     *
     * @param key The key with 16, 24 or 32 bytes.
     * @param data
     * @return Encoded data
     */
    public static byte[] encryptAes(byte[] key, byte[] data) {
        init();
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM_AES, PROVIDER);
            Key skeySpec = generateAesKeySpec(key);
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
            byte[] encrypted = cipher.doFinal(data);
            return encrypted;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Encrypt the String using UTF8 encoding and return a base64 encoded string.
     *
     * @param key
     * @param data
     * @return Base64 encoded encrypted string
     */
    public static String encryptAes(byte[] key, String data) {
        byte[] enc = encryptAes(key, data.getBytes(STRING_ENCODING));
        return encodeBase64(enc);
    }

    /**
     * Creates a key object from bytes.
     *
     * @param key
     * @return The bytes key as object
     */
    public static Key generateAesKeySpec(byte[] key) {
        Key k = new SecretKeySpec(key, ALGORITHM_AES);
        return k;
    }

    /**
     * Decrypt a encrypted byte array.
     *
     * @param key
     * @param encrypted
     * @return original bytes
     */
    public static byte[] decryptAes(byte[] key, byte[] encrypted) {
        init();
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM_AES, PROVIDER);
            Key skeySpec = generateAesKeySpec(key);
            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
            byte[] decrypted = cipher.doFinal(encrypted);
            return decrypted;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Decrypt a base64 encoded string and return the ariginal string. String encoding is UTF8.
     *
     * @param key
     * @param encrypted
     * @return The original string
     */
    public static String decryptAes(byte[] key, String encrypted) {
        byte[] dec = decryptAes(key, decodeBase64(encrypted));
        return new String(dec, STRING_ENCODING);
    }

    /**
     * Generating RSA keys needs a lot of resources (ca 100ms per key). Therefore you can use a
     * keypool. The keypool will regularly renew the keys.
     *
     * @return A key from the pool
     */
    public static synchronized KeyPair getRsaKeyFromPool() {
        if (MPeriod.isTimeOut(keyPoolUpdate, CFG_POOL_UPDATE_TIME.value())) {
            if (keyPool.size() > 0) keyPool.removeFirst();
            keyPoolUpdate = System.currentTimeMillis();
        }
        if (keyPool.size() < CFG_POOL_SIZE.value()) {
            try {
                KeyPair key = generateRsaKey(RSA_KEY_SIZE_DEFAULT);
                keyPool.add(key);
                return key;
            } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                throw new RuntimeException(e);
            }
        }
        int pos = (int) (Math.random() * keyPool.size()); // use a simple random function
        return keyPool.get(pos);
    }

    public static KeyPair generateEccKey(ECC_SPEC spec) {
        init();
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM_ECC, PROVIDER);
            ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(spec.name().toLowerCase());
            keyGen.initialize(ecGenSpec, MRandom.get().getSecureRandom());
            KeyPair key = keyGen.generateKeyPair();
            return key;
        } catch (Exception t) {
            throw new RuntimeException(t);
        }
    }

    public static boolean validateSignature(PublicKey key, String in, String sign) {
        try {
            return validateSignature(
                    key,
                    new ByteArrayInputStream(in.getBytes(MString.CHARSET_CHARSET_UTF_8)),
                    sign);
        } catch (Exception t) {
            throw new RuntimeException(t);
        }
    }

    public static boolean validateSignature(PublicKey key, InputStream is, String sign) {
        try {
            byte[] encKey = key.getEncoded();
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_ECC, PROVIDER);
            PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

            Signature sig = Signature.getInstance(TRANSFORMATION_ECC, PROVIDER);
            sig.initVerify(pubKey);

            byte[] buffer = new byte[1024 * 10];
            while (true) {
                int len = is.read(buffer);
                if (len < 0) break;
                if (len == 0) MThread.sleep(200);
                else sig.update(buffer, 0, len);
            }
            PemBlock signBlock = PemUtil.parse(sign);
            return sig.verify(signBlock.getBytesBlock());
        } catch (Exception t) {
            throw new RuntimeException(t);
        }
    }

    public static String createSignature(PrivateKey key, String in) {
        try {
            return createSignature(
                    key, new ByteArrayInputStream(in.getBytes(MString.CHARSET_UTF_8)));
        } catch (Exception t) {
            throw new RuntimeException(t);
        }
    }

    public static String createSignature(PrivateKey key, InputStream is) {
        try {
            byte[] encKey = key.getEncoded();
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(encKey);
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_ECC, PROVIDER);
            PrivateKey privKey = keyFactory.generatePrivate(privKeySpec);

            Signature sig = Signature.getInstance(TRANSFORMATION_ECC, PROVIDER);
            sig.initSign(privKey);
            byte[] buffer = new byte[1024 * 10];
            while (true) {
                int len = is.read(buffer);
                if (len < 0) break;
                if (len == 0) MThread.sleep(200);
                else sig.update(buffer, 0, len);
            }
            PemBlockModel pem = new PemBlockModel(PemBlock.BLOCK_SIGN, sig.sign());
            pem.setString(PemBlock.METHOD, key.getAlgorithm());
            return pem.toString();
        } catch (Exception t) {
            throw new RuntimeException(t);
        }
    }
}
