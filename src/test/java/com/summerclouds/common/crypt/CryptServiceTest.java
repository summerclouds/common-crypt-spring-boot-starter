package com.summerclouds.common.crypt;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Collection;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.summerclouds.common.core.error.MException;
import org.summerclouds.common.core.internal.SpringSummerCloudsCoreAutoConfiguration;
import org.summerclouds.common.crypt.MCrypt;
import org.summerclouds.common.crypt.crypt.pem.PemBlock;
import org.summerclouds.common.crypt.crypt.pem.PemBlockList;
import org.summerclouds.common.crypt.crypt.pem.PemBlockModel;
import org.summerclouds.common.crypt.internal.SpringSummerCloudsCryptAutoConfiguration;
import org.summerclouds.common.crypt.util.SimplePemProcessContext;
import org.summerclouds.common.junit.TestCase;

@SpringBootTest(classes = {
		SpringSummerCloudsCoreAutoConfiguration.class,
		SpringSummerCloudsCryptAutoConfiguration.class
		},
properties = { 
		"org.summerclouds.crypt.cipher.enabled=true",
		"org.summerclouds.crypt.signer.enabled=true",
		"org.summerclouds.crypt.keychain.enabled=true"
}
)
public class CryptServiceTest extends TestCase {

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

	private final String signature =
            "-----BEGIN SIGNATURE-----\n"
                    + "PrivateKey: cb0b626c-d0a7-4715-8c08-77a75ee9dc14\n"
                    + "PublicKey: 881b7fe7-3bc3-4cd0-ab21-ea52e9d04174\n"
                    + "Method: ECC-BC\n"
                    + "Embedded: next\n"
                    + "Created: Tue Jun 05 22:06:04 CEST 2018\n"
                    + "\n"
                    + "MDYCGQCOpzpQuaNQk7p6/rEeKduOt9IzQmneXdsCGQD63pg/AJ\n"
                    + "F4C9VzDj44wWvROeqkSbDic/o=\n"
                    + "\n"
                    + "-----END SIGNATURE-----\n";

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

	private final String cipherBlock =
            "-----BEGIN CIPHER-----\n"
                    + "PrivateKey: 5fe815c6-954d-4dbf-b581-4dc6e05dc17c\n"
                    + "PublicKey: 12657d2c-b73a-4be0-a5a2-037d835697cb\n"
                    + "Encoding: utf-8\n"
                    + "Method: RSA-JCE\n"
                    + "Embedded: true\n"
                    + "Created: Tue Jun 05 22:27:22 CEST 2018\n"
                    + "\n"
                    + "Y6pGraTQaDa2CHiSosf3S+rnnUT1QM7q5pScU4e96+IBcKB0s7\n"
                    + "r16fedCEQMraYTi1XLcL78shq+OQZ28UAhZUc3ZtAwfdaZ97PB\n"
                    + "8bMJuhekhNr57yZ4cj+eLhtq70SzpHUL9ONuP2KNMgjH/sl5tv\n"
                    + "6zlCTgIT8FqeUyTNtAzmqG1LqjGpQjn9n4xggHpefAWB5Qzrlu\n"
                    + "8boiZcIP+kS0L9Tc2/HXBMoqHf/vHWLI8ynHPJYU/6SoS5Ka30\n"
                    + "p0cb9GHwEMZCkb393AcaaUXKd2c9Df9FE+uaUb0/FU99QalmoD\n"
                    + "ZAU8Y519BPVTB0gNWcRHrkxy8stAS2Mh8sAGLXcB60Zr0ZujdJ\n"
                    + "TkOM9nY/j5S/y1jNTfnL6DAjZ2x6639G4rRcoOUC0uEGmVYhZ7\n"
                    + "KW5sJ8LLbDVuATWDWFo4T/ZOLRRtr4s2Q6fPXUV+UuN5GPHJOB\n"
                    + "oW5+aO1RIVB9LGHHSQ7xsU888x/oukaWdGyx1EzkrpT94h60It\n"
                    + "wNkvX1pcaulf\n"
                    + "\n"
                    + "-----END CIPHER-----\n";

    @Test
    public void testCiphersAvailable() throws MException {
    	Collection<String> list = MCrypt.getCipherList();
    	System.out.println( list );
    	assertEquals(5, list.size());
    }

    @Test
    public void testSignerAvailable() throws MException {
    	Collection<String> list = MCrypt.getSignerList();
    	System.out.println( list );
    	assertEquals(3, list.size());
    }
    
    @Test
    public void testEmbeddedCipher() throws MException {
        System.out.println(">>> testEmbeddedCipher");

        SimplePemProcessContext context = new SimplePemProcessContext();

        PemBlockList list = new PemBlockList(privKeyCipher + cipherBlock);
        // System.out.println(list);

//        CryptApiImpl api =
//                new CryptApiImpl() {
//                    @Override
//                    public CipherProvider getCipher(String cipher) throws NotFoundException {
//                        if (cipher.equals("RSA-JCE")) return new JavaRsaCipher();
//                        throw new NotFoundException(cipher);
//                    }
//                };
        MCrypt.processPemBlocks(context, list);

        assertEquals(contentBlock, context.getLastSecret().value());
    }

    @Test
    public void testSign() throws MException {
        System.out.println(">>> testSign");

        //		EccSigner signer = new EccSigner();
        //		boolean valid = signer.validate(PemUtil.toKey(pubKeySign), contentBlock.toString(), new
        // PemBlockModel().parse(signature));
        //		if (!valid) throw new MException("not valid");

        SimplePemProcessContext context = new SimplePemProcessContext();

        PemBlockList list = new PemBlockList(pubKeySign + signature + contentBlock);
        // System.out.println(list);

        MCrypt.processPemBlocks(context, list);
    }

}
