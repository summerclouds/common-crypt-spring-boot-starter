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

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

import org.springframework.util.Assert;
import org.summerclouds.common.core.cfg.BeanRefMap;
import org.summerclouds.common.core.error.MException;
import org.summerclouds.common.core.error.MRuntimeException;
import org.summerclouds.common.core.error.NotFoundException;
import org.summerclouds.common.core.error.RC;
import org.summerclouds.common.core.log.Log;
import org.summerclouds.common.core.tool.MBigMath;
import org.summerclouds.common.core.tool.MCast;
import org.summerclouds.common.core.tool.MFile;
import org.summerclouds.common.core.tool.MMath;
import org.summerclouds.common.core.tool.MRandom;
import org.summerclouds.common.core.tool.MString;
import org.summerclouds.common.core.tool.MThread;
import org.summerclouds.common.core.util.SecureString;
import org.summerclouds.common.crypt.cipher.CipherProvider;
import org.summerclouds.common.crypt.crypt.AsyncKey;
import org.summerclouds.common.crypt.crypt.CipherBlockAdd;
import org.summerclouds.common.crypt.crypt.CipherBlockRotate;
import org.summerclouds.common.crypt.crypt.CipherDecodeAsync;
import org.summerclouds.common.crypt.crypt.CipherEncodeAsync;
import org.summerclouds.common.crypt.crypt.CipherInputStream;
import org.summerclouds.common.crypt.crypt.CipherOutputStream;
import org.summerclouds.common.crypt.crypt.SaltInputStream;
import org.summerclouds.common.crypt.crypt.SaltOutputStream;
import org.summerclouds.common.crypt.crypt.pem.PemBlock;
import org.summerclouds.common.crypt.crypt.pem.PemBlockList;
import org.summerclouds.common.crypt.crypt.pem.PemKey;
import org.summerclouds.common.crypt.crypt.pem.PemPriv;
import org.summerclouds.common.crypt.crypt.pem.PemPub;
import org.summerclouds.common.crypt.crypt.pem.PemUtil;
import org.summerclouds.common.crypt.signer.SignerProvider;

/**
 * This tool is implementing functions to work with encryption and obfuscation to protect data. The
 * algorithm is implemented separate to the usual java.security package. If you want to use the save
 * and proven java implementation do not use this tool. With this tool you do not need any high
 * security patch for your java JRE.
 *
 * <p>You need to provide the bouncycastle bcprov-jdk15on library to read keys from ASN1 encoded
 * files.
 *
 * @author mikehummel
 */
public class MCrypt {

    public static final String PASSPHRASE = "passphrase";
    public static final String LENGTH = "length";
    private static BeanRefMap<CipherProvider> cipherProviders =
            new BeanRefMap<>(CipherProvider.class);
    private static BeanRefMap<SignerProvider> signerProviders =
            new BeanRefMap<>(SignerProvider.class);

    private static Log log = Log.getLog(MCrypt.class);

    public static CipherProvider getCipherByName(String name) throws MException {
        Assert.hasText(name, "cipher name must be set");

        // map to current version - not final
        if (!name.endsWith("-01")) name = name + "-01";

        Map<String, CipherProvider> map = cipherProviders.beans();
        for (CipherProvider provider : map.values())
            if (name.equals(provider.getName())) return provider;
        throw new NotFoundException("cipher {1} not found", name);
    }

    public static CipherProvider getCipherForKey(String key) throws MException {

        PemBlock pem = PemUtil.parse(key);
        // check for cipher key ??
        String method = pem.getString(PemBlock.METHOD);
        // legacy method mappings??
        return getCipherByName(method);
    }

    public static SignerProvider getSignerByName(String name) throws MException {
        Assert.hasText(name, "signer name must be set");

        // map to current version - not final
        if (!name.endsWith("-01")) name = name + "-01";

        Map<String, SignerProvider> map = signerProviders.beans();
        for (SignerProvider provider : map.values())
            if (name.equals(provider.getName())) return provider;
        throw new NotFoundException("signer {1} not found", name);
    }

    public static SignerProvider getSignerForKey(String key) throws MException {
        PemBlock pem = PemUtil.parse(key);
        // check for signer key ??
        String method = pem.getString(PemBlock.METHOD);
        // legacy method mappings??
        return getSignerByName(method);
    }

    public static String encrypt(String publicKey, String content) throws MException {
        PemKey key = PemUtil.toKey(publicKey);
        // check for cipher key ??
        String method = key.getString(PemBlock.METHOD);
        // legacy method mappings??
        CipherProvider cipher = getCipherByName(method);
        PemBlock res = cipher.encrypt(key, content);
        return res.toString();
    }

    public static String decrypt(String privateKey, String passphrase, String content)
            throws MException {
        PemKey key = PemUtil.toKey(privateKey);
        PemBlock contentPem = PemUtil.parse(content);
        // check for cipher key ??
        String method = key.getString(PemBlock.METHOD);
        // legacy method mappings??
        CipherProvider cipher = getCipherByName(method);
        String res = cipher.decrypt(key, contentPem, passphrase);
        return res;
    }

    public static String sign(String privateKey, String passphrase, String content)
            throws MException {
        PemKey key = PemUtil.toKey(privateKey);
        // check for cipher key ??
        String method = key.getString(PemBlock.METHOD);
        // legacy method mappings??
        SignerProvider signer = getSignerByName(method);
        PemBlock res = signer.sign(key, content, passphrase);
        return res.toString();
    }

    public static boolean validate(String publicKey, String signature, String content)
            throws MException {
        PemKey key = PemUtil.toKey(publicKey);
        PemBlock signPem = PemUtil.parse(signature);
        // check for cipher key ??
        String method = key.getString(PemBlock.METHOD);
        // legacy method mappings??
        SignerProvider signer = getSignerByName(method);
        boolean res = signer.validate(key, content, signPem);
        return res;
    }

    /**
     * Load a private key from file.
     *
     * @param file
     * @return the key object
     * @throws IOException
     */
    public static AsyncKey loadPrivateRsaKey(File file) throws IOException {
        String key = MFile.readFile(file);
        return loadPrivateRsaKey(key);
    }

    /**
     * Load a public key from file.
     *
     * @param file
     * @return the key object
     * @throws IOException
     */
    public static AsyncKey loadPublicRsaKey(File file) throws IOException {
        String key = MFile.readFile(file);
        return loadPublicRsaKey(key);
    }

    /**
     * Load a RSA private key into a AsyncKey object.
     *
     * @param key key as ASN1 encoded string containing "-----BEGIN RSA PRIVATE KEY-----"
     * @return Corresponding key object
     * @throws IOException If the key start or stop token was not found
     */
    public static AsyncKey loadPrivateRsaKey(String key) throws IOException {
        return Asn1Util.loadPrivateRsaKey(key);
    }

    /**
     * Load a RSA public key into a AsyncKey object.
     *
     * @param key key as ASN1 encoded string containing "-----BEGIN RSA PUBLIC KEY-----"
     * @return Corresponding key object
     * @throws IOException If the key start or stop token was not found
     */
    public static AsyncKey loadPublicRsaKey(String key) throws IOException {
        return Asn1Util.loadPublicRsaKey(key);
    }

    /*
     * public static AsyncKey createKeyPair(BigInteger prime1, BigInteger prime2) {
     * // (D * E) % z = 1 BigInteger n = prime1.multiply(prime2); BigInteger z =
     * prime1.subtract(BigInteger.ONE).multiply( prime2.subtract(BigInteger.ONE) );
     * BigInteger e = MBigMath.computeDfromE(privateExponent, z); BigInteger d =
     * MBigMath.computeDfromE(publicExponent, z);
     *
     * return new AsyncKey(n, publicExponent, privateExponent, prime1, prime2, e, d,
     * null); }
     */
    /**
     * Encode data using a RSA like algorithm. It's not using the java implementation.
     *
     * @param key public key
     * @param in clear data
     * @return encoded data
     * @throws IOException
     */
    public static BigInteger encode(AsyncKey key, BigInteger in) throws IOException {
        if (in.signum() == -1) throw new IOException("Negative values are not allowed");
        BigInteger encoded = MBigMath.binaryPow(in, key.getPublicExponent(), key.getModulus());
        return encoded;
    }

    /**
     * Encode data using a RSA like algorithm. It's not using the java implementation.
     *
     * @param key public key
     * @param in clear data
     * @return encoded and Base91 encoded string
     * @throws IOException
     */
    public static String encodeWithSalt(AsyncKey key, String in) throws IOException {
        byte[] org = MString.toBytes(in);
        byte[] org2 = new byte[org.length + 1];
        byte salt = MRandom.getByte();
        org2[0] = salt;
        for (int i = 0; i < org.length; i++) org2[i + 1] = MMath.addRotate(org[i], salt);
        BigInteger[] enc = encodeBytes(key, org2);
        String b = MBigMath.toBase91(enc);
        return "A" + b;
    }

    /**
     * Encode data using a RSA like algorithm. It's not using the java implementation.
     *
     * @param key public key
     * @param in clear data
     * @return encoded and Base91 encoded string
     * @throws IOException
     */
    public static String encode(AsyncKey key, String in) throws IOException {
        byte[] org = MString.toBytes(in);
        BigInteger[] enc = encodeBytes(key, org);
        String b = MBigMath.toBase91(enc);
        return b;
    }

    /**
     * Encode data using a RSA like algorithm. It's not using the java implementation.
     *
     * @param key public key
     * @param in clear data
     * @return encoded data
     * @throws IOException
     */
    public static BigInteger[] encodeBytes(AsyncKey key, byte[] in) throws IOException {
        CipherEncodeAsync encoder = new CipherEncodeAsync(key, MRandom.get());
        for (int i = 0; i < in.length; i++) encoder.write(in[i]);
        encoder.close();
        return encoder.toBigInteger();
    }

    /**
     * Encode data using a RSA like algorithm. It's not using the java implementation.
     *
     * @param key public key
     * @param in clear data
     * @return encoded data
     * @throws IOException
     */
    public static BigInteger[] encodeBytes(AsyncKey key, BigInteger[] in) throws IOException {
        BigInteger[] out = new BigInteger[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = encode(key, in[i]);
        }
        return out;
    }

    /**
     * Decode one byte using the private key.
     *
     * @param key private key
     * @param in encoded byte
     * @return decoded byte
     * @throws IOException
     */
    public static BigInteger decode(AsyncKey key, BigInteger in) throws IOException {
        if (in.signum() == -1) throw new IOException("Negative values not allowed");
        BigInteger decoded = MBigMath.binaryPow(in, key.getPrivateExponent(), key.getModulus());
        return decoded;
    }

    /**
     * Decode the data using Base91 byte encoding and the private key from 'key' using a RSA like
     * algorithm. It's not the java implementation used.
     *
     * @param key private key
     * @param in the encoded data presentation
     * @return the decoded string
     * @throws IOException
     */
    public static String decodeWithSalt(AsyncKey key, String in) throws IOException {
        BigInteger[] benc = MBigMath.fromBase91Array(in.substring(1));
        byte[] enc = MCrypt.decodeBytes(key, benc);
        if (in.charAt(0) == 'A') {
            byte[] enc2 = new byte[enc.length - 1];
            byte salt = enc[0];
            for (int i = 0; i < enc2.length; i++) enc2[i] = MMath.subRotate(enc[i + 1], salt);
            return MString.toString(enc2);
        } else throw new IOException("Unknown salt algorithm");
    }

    /**
     * Decode the data using Base91 byte encoding and the private key from 'key' using a RSA like
     * algorithm. It's not the java implementation used.
     *
     * @param key private key
     * @param in the encoded data presentation
     * @return the decoded string
     * @throws IOException
     */
    public static String decode(AsyncKey key, String in) throws IOException {
        BigInteger[] benc = MBigMath.fromBase91Array(in);
        byte[] enc = MCrypt.decodeBytes(key, benc);
        return MString.toString(enc);
    }

    /**
     * Decode the data using the private key from 'key' using a RSA like algorithm. It's not the
     * java implementation used.
     *
     * @param key private key
     * @param in encoded data
     * @return decoded array of data
     * @throws IOException
     */
    public static BigInteger[] decode(AsyncKey key, BigInteger[] in) throws IOException {
        BigInteger[] out = new BigInteger[in.length];
        for (int i = 0; i < in.length; i++) out[i] = decode(key, in[i]);
        return out;
    }

    /**
     * Decode data using the private key from 'key' using a RSA like algorithm. It's not the java
     * implementation used.
     *
     * @param key private key
     * @param in encoded data
     * @return decoded array of data.
     * @throws IOException
     */
    public static byte[] decodeBytes(AsyncKey key, BigInteger[] in) throws IOException {
        CipherDecodeAsync decoder = new CipherDecodeAsync(key);
        for (int i = 0; i < in.length; i++) decoder.write(in[i]);
        decoder.close();
        return decoder.toBytes();
    }

    /**
     * Create a random block using the MRandom service.
     *
     * @param size
     * @return CipherBlockRotate
     */
    public static CipherBlockRotate createRandomCipherBlockRotate(int size) {
        CipherBlockRotate out = new CipherBlockRotate(size);
        byte[] b = out.getBlock();
        for (int i = 0; i < b.length; i++) b[i] = MRandom.getByte();
        return out;
    }

    /**
     * Create a output stream automatically encode the stream with the pass phrase.
     *
     * @param parent
     * @param passphrase
     * @return OutputStream
     * @throws IOException
     */
    public static OutputStream createCipherOutputStream(OutputStream parent, String passphrase)
            throws IOException {
        return createCipherOutputStream(parent, passphrase, 3);
    }

    public static OutputStream createCipherOutputStream(
            OutputStream parent, String passphrase, int version) throws IOException {
        if (passphrase == null || passphrase.length() < 1)
            throw new IOException("passphrase not set");
        if (passphrase.length() < 4) throw new IOException("passphrase smaller then 4");
        byte[] p = MString.toBytes(passphrase);

        if (version < 2 || version > 3) throw new IOException("Cipher version unknown: " + version);

        parent.write('M');
        parent.write('C');
        parent.write('S');
        parent.write(version); // version

        if (version == 2) {
            CipherBlockAdd cipher = new CipherBlockAdd(p);
            return new SaltOutputStream(
                    new CipherOutputStream(parent, cipher),
                    MRandom.get(),
                    p.length - (MRandom.getInt() % (p.length / 2)),
                    true);
        }
        if (version == 3) {
            // extend passphrase
            byte pSalt = MRandom.getByte();
            String md5 = md5(pSalt + passphrase);
            p = MString.toBytes(md5 + passphrase);
            parent.write(MMath.unsignetByteToInt(pSalt));
            CipherBlockAdd cipher = new CipherBlockAdd(p);
            return new SaltOutputStream(
                    new CipherOutputStream(parent, cipher),
                    MRandom.get(),
                    p.length - (MRandom.getInt() % (p.length / 2)),
                    true);
        }
        throw new IOException("Cipher version unknown: " + version);
    }

    /**
     * Create a stream to decode a data stream with a simple pass phrase using
     * createCipherOutputStream.
     *
     * @param parent
     * @param passphrase
     * @return new input stream
     * @throws IOException
     */
    public static InputStream createCipherInputStream(InputStream parent, String passphrase)
            throws IOException {
        if (passphrase == null || passphrase.length() < 1)
            throw new IOException("passphrase not set");
        if (passphrase.length() < 4) throw new IOException("passphrase smaller then 4");
        if (parent.read() != 'M') throw new IOException("not a crypt stream header");
        if (parent.read() != 'C') throw new IOException("not a crypt stream header");
        if (parent.read() != 'S') throw new IOException("not a crypt stream header");
        int version = parent.read();
        if (version == 1) {
            int iSalt = parent.read();
            if (iSalt < 0) throw new EOFException();
            byte[] p = MString.toBytes(passphrase);
            byte salt = MMath.subRotate((byte) iSalt, p[0]);

            for (int i = 0; i < p.length; i++) p[i] = MMath.addRotate(p[i], salt);

            CipherBlockAdd cipher = new CipherBlockAdd(p);
            return new CipherInputStream(parent, cipher);
        } else if (version == 2) {
            byte[] p = MString.toBytes(passphrase);
            CipherBlockAdd cipher = new CipherBlockAdd(p);
            return new SaltInputStream(new CipherInputStream(parent, cipher), true);
        } else if (version == 3) {
            byte pSalt = (byte) parent.read();
            String md5 = md5(pSalt + passphrase);
            byte[] p = MString.toBytes(md5 + passphrase);
            CipherBlockAdd cipher = new CipherBlockAdd(p);
            return new SaltInputStream(new CipherInputStream(parent, cipher), true);
        } else throw new IOException("unsupported crypt stream version: " + version);
    }

    /**
     * Only obfuscate the byte array. The obfuscation is used to confuse the reader but not to
     * secure the data.
     *
     * <p>TODO: Create more complex algorithm
     *
     * @param in
     * @return an obfuscated string
     */
    public static byte[] obfuscate(byte[] in) {
        if (in == null) return null;
        if (in.length < 1) return in;
        byte[] out = new byte[in.length + 1];
        byte salt = MRandom.getByte();
        out[0] = salt;
        for (int i = 0; i < in.length; i++) out[i + 1] = MMath.addRotate(in[i], salt);
        return out;
    }

    /**
     * Decode obfuscated byte array.
     *
     * @param in
     * @return original byte array
     */
    public static byte[] unobfuscate(byte[] in) {
        if (in == null) return null;
        if (in.length < 2) return in;
        byte[] out = new byte[in.length - 1];
        byte salt = in[0];
        for (int i = 1; i < in.length; i++) out[i - 1] = MMath.subRotate(in[i], salt);
        return out;
    }

    /**
     * Returns the maximum amount of bytes that can be encrypted at once.
     *
     * @param modulus
     * @return maximum byte length
     */
    public static int getMaxLoad(BigInteger modulus) {
        return modulus.bitLength() / 8;
    }

    public static String md5(String real) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("MD5");
            md.update(real.getBytes(MString.CHARSET_CHARSET_UTF_8));
            return MCast.toBinaryString(md.digest());
        } catch (NoSuchAlgorithmException e) {
            log.w(e);
        }
        return null;
    }

    public static String sha256(String text) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedhash = digest.digest(text.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder(2 * encodedhash.length);
            for (int i = 0; i < encodedhash.length; i++) {
                String hex = Integer.toHexString(0xff & encodedhash[i]);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            text = hexString.toString();
            return text;
        } catch (Exception e) {
            log.w(e);
        }
        return null;
    }

    public static String sha256(InputStream is) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[1024 * 10];
            while (true) {
                int len = is.read(buffer);
                if (len < 0) break;
                if (len == 0) MThread.sleep(200);
                else digest.update(buffer, 0, len);
            }
            byte[] hash = digest.digest();
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            log.w(e);
        }
        return null;
    }

    /**
     * Create a salt and create a md5 using the salt. The first 4 characters represent the salt.
     *
     * @param real
     * @return salt and md5
     */
    public static String md5WithSalt(String real) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] salt = new byte[2];
            salt[0] = MRandom.getByte();
            salt[1] = MRandom.getByte();
            md.update(salt);
            md.update(real.getBytes(MString.CHARSET_CHARSET_UTF_8));
            return MCast.toBinaryString(salt) + MCast.toBinaryString(md.digest());
        } catch (NoSuchAlgorithmException e) {
            log.w(e);
        }
        return null;
    }

    /**
     * Check if the md5 and the real are the same. The md5 must be created with md5Salt before.
     *
     * @param md5
     * @param real
     * @return true if the both values are the same and no exception was thrown
     */
    public static boolean validateMd5WithSalt(String md5, String real) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            // take salt from md5
            byte[] salt = MCast.fromBinaryString(md5.substring(0, 4));
            // calculate md5
            md.update(salt);
            md.update(real.getBytes(MString.CHARSET_CHARSET_UTF_8));
            String realMd5 = MCast.toBinaryString(md.digest());
            // compare
            return realMd5.equals(md5.substring(4));
        } catch (Exception e) {
            log.t(e);
        }
        return false;
    }

    private static final int MAX_SPACE = 10;
    private static final int PEPPER_SIZE = 10;

    /**
     * Encode the byte array synchronous using the pass phrase. The encryption is not stable, two
     * encryptions of the same sample will result in different encryptions.
     *
     * @param passphrase
     * @param in
     * @return encoded byte array
     */
    public static byte[] encode(String passphrase, byte[] in) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] pp = passphrase.getBytes(MString.CHARSET_CHARSET_UTF_8);
        int ppPos = 0;
        byte salt = MRandom.getByte();

        // save salt
        byte o = MMath.addRotate(salt, pp[ppPos]);
        ppPos = (ppPos + 1) % pp.length;
        out.write(o);

        for (int pos = 0; pos < in.length; pos++) {
            byte space = (byte) (MRandom.getInt() % MAX_SPACE);
            // save space
            o = MMath.addRotate(space, pp[ppPos]);
            o = MMath.addRotate(o, salt);
            ppPos = (ppPos + 1) % pp.length;
            out.write(o);
            // fill space
            for (int j = 0; j < space; j++) out.write(MRandom.getByte());
            // write one byte
            o = MMath.addRotate(in[pos], pp[ppPos]);
            o = MMath.addRotate(o, salt);
            ppPos = (ppPos + 1) % pp.length;
            out.write(o);
        }
        // one more trailing space
        byte space = (byte) (MRandom.getInt() % MAX_SPACE);
        // save space
        o = MMath.addRotate(space, pp[ppPos]);
        o = MMath.addRotate(o, salt);
        ppPos = (ppPos + 1) % pp.length;
        out.write(o);
        // fill space
        for (int j = 0; j < space; j++) out.write(MRandom.getByte());

        return out.toByteArray();
    }

    /**
     * Decode the byte array synchronous using the pass phrase.
     *
     * @param passphrase
     * @param in
     * @return decoded byte array
     */
    public static byte[] decode(String passphrase, byte[] in) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] pp = passphrase.getBytes(MString.CHARSET_CHARSET_UTF_8);
        int ppPos = 0;

        // read salt
        byte salt = MMath.subRotate(in[0], pp[ppPos]);
        ppPos = (ppPos + 1) % pp.length;

        int mode = 0;
        byte space = 0;
        for (int pos = 1; pos < in.length; pos++) {
            if (mode == 0) {
                // read space length
                byte o = MMath.subRotate(in[pos], salt);
                space = MMath.subRotate(o, pp[ppPos]);
                ppPos = (ppPos + 1) % pp.length;
                if (space == 0) mode = 2;
                else mode = 1;
            } else if (mode == 1) {
                space--;
                if (space <= 0) mode = 2;
            } else if (mode == 2) {
                byte o = MMath.subRotate(in[pos], salt);
                o = MMath.subRotate(o, pp[ppPos]);
                ppPos = (ppPos + 1) % pp.length;
                out.write(o);
                mode = 0;
            }
        }

        return out.toByteArray();
    }

    /**
     * Add a pepper string in front of the content
     *
     * @param content
     * @return pepper and content
     */
    public static String addPepper(String content) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < PEPPER_SIZE; i++) {
            char c = MRandom.getChar();
            if (c == '+') c = 'x'; // for secure
            sb.append(c);
        }
        sb.append('+');
        sb.append(content);
        return sb.toString();
    }

    /**
     * Remove a pepper string from front of content
     *
     * @param withPepper pepper + content
     * @return content only
     */
    public static String removePepper(String withPepper) {
        int p = withPepper.indexOf('+');
        if (p < 0) return withPepper;
        return withPepper.substring(p + 1);
    }

    /**
     * Add a pepper array in front of a byte array
     *
     * @param content
     * @return pepper and content as new array
     */
    public static byte[] addPepper(byte[] content) {
        byte[] out = new byte[content.length + 1 + PEPPER_SIZE];
        for (int i = 0; i < PEPPER_SIZE; i++) {
            byte b = MRandom.getByte();
            if (b == 0) b = 1;
            out[i] = b;
        }
        out[PEPPER_SIZE] = 0;
        System.arraycopy(content, 0, out, PEPPER_SIZE + 1, content.length);
        return out;
    }

    /**
     * Remove a pepper from content
     *
     * @param withPepper
     * @return new array with content only
     */
    public static byte[] removePepper(byte[] withPepper) {
        for (int i = 0; i < withPepper.length; i++) {
            if (withPepper[i] == 0) {
                byte[] out = new byte[withPepper.length - i - 1];
                System.arraycopy(withPepper, i + 1, out, 0, out.length);
                return out;
            }
        }
        // need to clone the pepper - behavior is to return an new array
        // so inserted array could be manipulated afterwards without changing this
        // result
        byte[] out = new byte[withPepper.length];
        System.arraycopy(withPepper, 0, out, 0, withPepper.length);
        return withPepper;
    }

    public static UUID toUuidHash(String in) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(in.getBytes(MString.CHARSET_CHARSET_UTF_8));
            byte[] md5 = md.digest();

            long a = md5[0] * 256 * md5[1] + 256 * 256 * md5[2] + 256 * 256 * 256 * md5[3];
            long b = md5[4] * 256 * md5[5] + 256 * 256 * md5[6] + 256 * 256 * 256 * md5[7];

            return new UUID(a, b);
        } catch (Exception t) {
            throw new MRuntimeException(RC.STATUS.ERROR, in, t);
        }
    }

    public static void processPemBlocks(PemProcessContext context, PemBlockList list)
            throws MException {
        // iterate all blocks
        int index = 0;
        while (index < list.size()) {
            PemBlock block = list.get(index);
            log.t("process", block);
            Object res = processPemBlock(context, block);
            if (PemUtil.isCipher(block) && block.getBoolean(PemBlock.EMBEDDED, false)) {
                if (res == null) throw new NotDecryptedException(block);
                PemBlockList insert = new PemBlockList(((SecureString) res).value());
                log.t("insert", insert);
                list.addAll(index + 1, insert);
            } else if (PemUtil.isSign(block) && block.getBoolean(PemBlock.EMBEDDED, false)) {
                if (res == null) throw new CryptException("sign key not found", block);
                PemPub key = (PemPub) res;
                // validate against the rest of the block list
                String text = list.toString(index + 1, Integer.MAX_VALUE);

                SignerProvider api = getSignerByName(block.getString(PemBlock.METHOD));
                boolean valid = api.validate(key, text, block);
                if (!valid) throw new SignNotValidException(block);
                context.foundValidated(block);
            } else if (PemUtil.isSign(block)
                    && block.getString(PemBlock.EMBEDDED, "").equals("next")) {
                if (res == null) throw new CryptException("sign key not found", block);
                PemPub key = (PemPub) res;
                // validate against the next block
                PemBlock next = list.get(index + 1);
                String text = next.toString();
                SignerProvider api = getSignerByName(block.getString(PemBlock.METHOD));
                boolean valid = api.validate(key, text, block);
                if (!valid) throw new SignNotValidException(block);
                context.foundValidated(block);
            }
            index++;
        }
    }

    public static Object processPemBlock(PemProcessContext context, PemBlock block)
            throws MException {
        if (PemUtil.isCipher(block)) {
            // process encrypted content
            PemPriv keyKey = null;
            String keyId = null;
            boolean isSymetric =
                    block.getBoolean(PemBlock.SYMMETRIC, block.isProperty(PemBlock.KEY_ID));
            if (isSymetric) {
                keyId = block.getString(PemBlock.KEY_ID, null);
                if (keyId == null) {
                    log.d("key id not found", block);
                    context.errorKeyNotFound(block);
                    return null;
                }
            } else {
                keyId = block.getString(PemBlock.PRIV_ID, null);
                if (keyId == null) {
                    String pubId = block.getString(PemBlock.PUB_ID, null);
                    if (pubId == null) {
                        log.d("public key not found", block);
                        context.errorKeyNotFound(block);
                        return null;
                    }
                    keyId = context.getPrivateIdForPublicKeyId(pubId);
                    if (keyId == null) {
                        log.d("private key not found for public key", block);
                        context.errorKeyNotFound(block);
                        return null;
                    }
                }
            }
            keyKey = context.getPrivateKey(keyId);
            if (keyKey == null) {
                log.d("private key not found", block);
                context.errorKeyNotFound(block);
                return null;
            }

            CipherProvider api = getCipherByName(block.getString(PemBlock.METHOD));
            String decoded = api.decrypt(keyKey, block, context.getPassphrase(keyId, block));
            SecureString sec = new SecureString(decoded);
            decoded = "";
            context.foundSecret(block, sec);
            return sec;
        } else if (PemUtil.isSign(block)) {
            // no content to validate - not possible in this moment, but will check the key
            String keyId = block.getString(PemBlock.PUB_ID, null);
            if (keyId == null) {
                String privId = block.getString(PemBlock.PRIV_ID, null);
                if (privId == null) {
                    log.d("private key not found", block);
                    context.errorKeyNotFound(block);
                    return null;
                }
                keyId = context.getPrivateIdForPublicKeyId(privId);
                if (keyId == null) {
                    log.d("public key not found for private key", block);
                    context.errorKeyNotFound(block);
                    return null;
                }
            }
            PemPub keyKey = context.getPublicKey(keyId);
            if (keyKey == null) {
                log.d("public key not found", block);
                context.errorKeyNotFound(block);
                return null;
            }
            return keyKey;
        }
        if (PemUtil.isPubKey(block)) {
            context.foundPublicKey(block);
            return block;
        } else if (PemUtil.isPrivKey(block)) {
            context.foundPrivateKey(block);
            return block;
        } else if (PemUtil.isHash(block)) {
            context.foundHash(block);
        } else if (PemUtil.isContent(block)) {
        } else log.w("unknown block type", block.getName());
        return null;
    }

    public static Set<String> getCipherList() {
        Map<String, CipherProvider> map = cipherProviders.beans();
        Set<String> out = new TreeSet<>();
        map.values().forEach(i -> out.add(i.getName()));
        return out;
    }

    public static Set<String> getSignerList() {
        Map<String, SignerProvider> map = signerProviders.beans();
        Set<String> out = new TreeSet<>();
        map.values().forEach(i -> out.add(i.getName()));
        return out;
    }
}
