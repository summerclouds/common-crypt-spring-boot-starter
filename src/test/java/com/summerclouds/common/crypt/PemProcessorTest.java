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
package com.summerclouds.common.crypt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.summerclouds.common.core.error.MException;
import org.summerclouds.common.core.parser.ParseException;
import org.summerclouds.common.crypt.MBouncy;
import org.summerclouds.common.crypt.bc.EccSigner;
import org.summerclouds.common.crypt.bc.JavaRsaCipher;
import org.summerclouds.common.crypt.crypt.pem.PemBlock;
import org.summerclouds.common.crypt.crypt.pem.PemBlockModel;
import org.summerclouds.common.crypt.crypt.pem.PemUtil;

public class PemProcessorTest {

    private final String content =
            "Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua.";

    private final String pubKeySign =
            "-----BEGIN PUBLIC KEY-----\n"
                    + "PrivateKey: cb0b626c-d0a7-4715-8c08-77a75ee9dc14\n"
                    + "Ident: 881b7fe7-3bc3-4cd0-ab21-ea52e9d04174\n"
                    + "Format: X.509\n"
                    + "StdName: prime192v1\n"
                    + "Method: ECC-BC\n"
                    + "\n"
                    + "MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEqqyclMzGZTjvKS\n"
                    + "+URxjdm0ueWyuR+3msXeGROatE5+hK0lMzoTLuHazRW2ar2Mz5\n"
                    + "\n"
                    + "-----END PUBLIC KEY-----\n";

    private final String privKeySign =
            "-----BEGIN PRIVATE KEY-----\n"
                    + "Ident: cb0b626c-d0a7-4715-8c08-77a75ee9dc14\n"
                    + "StdName: prime192v1\n"
                    + "Format: PKCS#8\n"
                    + "PublicKey: 881b7fe7-3bc3-4cd0-ab21-ea52e9d04174\n"
                    + "Method: ECC-BC\n"
                    + "\n"
                    + "MHsCAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQEEYTBfAgEBBBjDOv\n"
                    + "ScMgourQ6rU8pDIG033kCUuHby9MygCgYIKoZIzj0DAQGhNAMy\n"
                    + "AASqrJyUzMZlOO8pL5RHGN2bS55bK5H7eaxd4ZE5q0Tn6ErSUz\n"
                    + "OhMu4drNFbZqvYzPk=\n"
                    + "\n"
                    + "-----END PRIVATE KEY-----\n";

//    private final String signature =
//            "-----BEGIN SIGNATURE-----\n"
//                    + "PrivateKey: cb0b626c-d0a7-4715-8c08-77a75ee9dc14\n"
//                    + "PublicKey: 881b7fe7-3bc3-4cd0-ab21-ea52e9d04174\n"
//                    + "Method: ECC-BC\n"
//                    + "Embedded: next\n"
//                    + "Created: Tue Jun 05 22:06:04 CEST 2018\n"
//                    + "\n"
//                    + "MDYCGQCOpzpQuaNQk7p6/rEeKduOt9IzQmneXdsCGQD63pg/AJ\n"
//                    + "F4C9VzDj44wWvROeqkSbDic/o=\n"
//                    + "\n"
//                    + "-----END SIGNATURE-----\n";

    private final String contentBlock =
            new PemBlockModel(PemBlock.BLOCK_CONTENT, content.getBytes()).toString();

    private final String privKeyCipher =
            "-----BEGIN PRIVATE KEY-----\n"
                    + "Ident: 5fe815c6-954d-4dbf-b581-4dc6e05dc17c\n"
                    + "Format: PKCS#8\n"
                    + "Length: 1024\n"
                    + "PublicKey: 12657d2c-b73a-4be0-a5a2-037d835697cb\n"
                    + "Method: RSA-JCE\n"
                    + "Created: Tue Jun 05 21:52:45 CEST 2018\n"
                    + "\n"
                    + "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAI\n"
                    + "gdxYtSYUlaVCv9zYPpiybNYLv2OSXZdBHqIDaTokJ5QCtb0rj4\n"
                    + "JH8+ngBLiBv1gx1wuwkPNdjDPFfUeP/mRLe/1jjravf4FMISX/\n"
                    + "bOlhd3OqsZYlGrZJieUvaIJ6zdqXKBwwADopBIp3ThMe+yTpSB\n"
                    + "KVIxswM5CEvjeyI+AYqXAgMBAAECgYA/1a6CM0U60GjvJJ0QQy\n"
                    + "OmM+Us4UFV1dBQYntu/Pe4swJ8ExkU9BKxth0FSGbxrccqtGaS\n"
                    + "zhZTrOQM0LFaWZRZ3ZimZUZ6G1UdScArApBNz2uGiou84tfnEL\n"
                    + "HJmqmG68nz8GWhfrIXx2ezPCauKMbbO6KfMmqxtGqGqeUfMRc/\n"
                    + "mQJBAPqgPXwxt/HUL+CAeA8AWv9myOyM03FXzd1Bhcl3wZkoGU\n"
                    + "Tg6qQ6dKnssCMlipPFK2+viRazqYiEg4LbsbRLSksCQQCLCPRH\n"
                    + "vnT1YBNVN/h3V7Jb0ETX0JeElP4w1NnQmBFFexh3buHev3g4ff\n"
                    + "4shSqxqi+eAiD0M12YUx05YqsmMtFlAkAiRMDDd4TgQxQczVQd\n"
                    + "MP5AR8yXU5YhvFDAvRHO/1nwWCREX8CVngyPo3ZeB+cP13jd95\n"
                    + "F2EjDPItdckC+XKGhLAkAEXjymgGJWTzVsSPziavvsjIeNLD2G\n"
                    + "adPuntFVD2IDh9GF9xLbl7JkO/kfVvO3bzxdv31fjrmTDpFtex\n"
                    + "8bbR9NAkBAQWpAQ1wsYznQFBIkMlLTt/rM8C3rBwMr+eLjmX3p\n"
                    + "JFdw7BXHVtGQrTeBHgchoMSXkYJXlDQTTmdJ0vBMpx6s\n"
                    + "\n"
                    + "-----END PRIVATE KEY-----\n";

    private final String pubKeyCipher =
            "-----BEGIN PUBLIC KEY-----\n"
                    + "Ident: 12657d2c-b73a-4be0-a5a2-037d835697cb\n"
                    + "Format: X.509\n"
                    + "PrivateKey: 5fe815c6-954d-4dbf-b581-4dc6e05dc17c\n"
                    + "Length: 1024\n"
                    + "Method: RSA-JCE\n"
                    + "Created: Tue Jun 05 21:52:45 CEST 2018\n"
                    + "\n"
                    + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCIHcWLUmFJWl\n"
                    + "Qr/c2D6YsmzWC79jkl2XQR6iA2k6JCeUArW9K4+CR/Pp4AS4gb\n"
                    + "9YMdcLsJDzXYwzxX1Hj/5kS3v9Y462r3+BTCEl/2zpYXdzqrGW\n"
                    + "JRq2SYnlL2iCes3alygcMAA6KQSKd04THvsk6UgSlSMbMDOQhL\n"
                    + "43siPgGKlwIDAQAB\n"
                    + "\n"
                    + "-----END PUBLIC KEY-----\n";

//    private final String cipherBlock =
//            "-----BEGIN CIPHER-----\n"
//                    + "PrivateKey: 5fe815c6-954d-4dbf-b581-4dc6e05dc17c\n"
//                    + "PublicKey: 12657d2c-b73a-4be0-a5a2-037d835697cb\n"
//                    + "Encoding: utf-8\n"
//                    + "Method: RSA-JCE\n"
//                    + "Embedded: true\n"
//                    + "Created: Tue Jun 05 22:27:22 CEST 2018\n"
//                    + "\n"
//                    + "Y6pGraTQaDa2CHiSosf3S+rnnUT1QM7q5pScU4e96+IBcKB0s7\n"
//                    + "r16fedCEQMraYTi1XLcL78shq+OQZ28UAhZUc3ZtAwfdaZ97PB\n"
//                    + "8bMJuhekhNr57yZ4cj+eLhtq70SzpHUL9ONuP2KNMgjH/sl5tv\n"
//                    + "6zlCTgIT8FqeUyTNtAzmqG1LqjGpQjn9n4xggHpefAWB5Qzrlu\n"
//                    + "8boiZcIP+kS0L9Tc2/HXBMoqHf/vHWLI8ynHPJYU/6SoS5Ka30\n"
//                    + "p0cb9GHwEMZCkb393AcaaUXKd2c9Df9FE+uaUb0/FU99QalmoD\n"
//                    + "ZAU8Y519BPVTB0gNWcRHrkxy8stAS2Mh8sAGLXcB60Zr0ZujdJ\n"
//                    + "TkOM9nY/j5S/y1jNTfnL6DAjZ2x6639G4rRcoOUC0uEGmVYhZ7\n"
//                    + "KW5sJ8LLbDVuATWDWFo4T/ZOLRRtr4s2Q6fPXUV+UuN5GPHJOB\n"
//                    + "oW5+aO1RIVB9LGHHSQ7xsU888x/oukaWdGyx1EzkrpT94h60It\n"
//                    + "wNkvX1pcaulf\n"
//                    + "\n"
//                    + "-----END CIPHER-----\n";

    @BeforeAll
    public static void setUp() throws Exception {
//        MApi.get().getLogFactory().setDefaultLevel(LEVEL.TRACE);
        MBouncy.init();
    }

    @Test
    public void testCreateCipher() throws ParseException, MException {
        System.out.println(">>> testCreateCipher");

        JavaRsaCipher cipher = new JavaRsaCipher();

        String text = contentBlock.toString();
        PemBlock enc = cipher.encrypt(PemUtil.toKey(pubKeyCipher), text);

        System.out.println(enc);

        String dec = cipher.decrypt(PemUtil.toKey(privKeyCipher), enc);

        assertEquals(text, dec);
    }

    @Test
    public void testCreateSign() throws MException {
        System.out.println(">>> testCreateSign");

        EccSigner signer = new EccSigner();

        String text = contentBlock.toString();
        PemBlock sign = signer.sign(PemUtil.toKey(privKeySign), text);

        System.out.println(sign);

        boolean valid = signer.validate(PemUtil.toKey(pubKeySign), text, sign);
        System.out.println(valid);
        assertTrue(valid, "Signer result is not valid");
    }

}
