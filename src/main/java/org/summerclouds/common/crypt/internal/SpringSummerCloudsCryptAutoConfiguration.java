package org.summerclouds.common.crypt.internal;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.summerclouds.common.core.crypt.IKeychain;
import org.summerclouds.common.core.log.PlainLog;
import org.summerclouds.common.crypt.MBouncy;
import org.summerclouds.common.crypt.bc.BouncyAesWithRsaCipher;
import org.summerclouds.common.crypt.bc.BouncyDsaSigner;
import org.summerclouds.common.crypt.bc.BouncyRsaCipher;
import org.summerclouds.common.crypt.bc.EccSigner;
import org.summerclouds.common.crypt.bc.JavaAesCipher;
import org.summerclouds.common.crypt.bc.JavaAesWithRsaCipher;
import org.summerclouds.common.crypt.bc.JavaDsaSigner;
import org.summerclouds.common.crypt.bc.JavaRsaCipher;
import org.summerclouds.common.crypt.cipher.CipherProvider;
import org.summerclouds.common.crypt.keychain.DefaultKeychain;
import org.summerclouds.common.crypt.signer.SignerProvider;

public class SpringSummerCloudsCryptAutoConfiguration {

	public SpringSummerCloudsCryptAutoConfiguration() {
		PlainLog.i("Start SpringSummerCloudsCryptAutoConfiguration");
    	MBouncy.init();
	}
	
	@Bean
	@ConditionalOnProperty(name="org.summerclouds.crypt.cipher.enable",havingValue="true")
	public CipherProvider bouncyAesWithRsaCipher() {
		return new BouncyAesWithRsaCipher();
	}
	
	@Bean
	@ConditionalOnProperty(name="org.summerclouds.crypt.cipher.enable",havingValue="true")
	public CipherProvider bouncyRsaCipher() {
		return new BouncyRsaCipher();
	}

	@Bean
	@ConditionalOnProperty(name="org.summerclouds.crypt.cipher.enable",havingValue="true")
	public CipherProvider javaAesCipher() {
		return new JavaAesCipher();
	}

	@Bean
	@ConditionalOnProperty(name="org.summerclouds.crypt.cipher.enable",havingValue="true")
	public CipherProvider javaAesWithRsaCipher() {
		return new JavaAesWithRsaCipher();
	}

	@Bean
	@ConditionalOnProperty(name="org.summerclouds.crypt.cipher.enable",havingValue="true")
	public CipherProvider javaRsaCipher() {
		return new JavaRsaCipher();
	}

	@Bean
	@ConditionalOnProperty(name="org.summerclouds.crypt.signer.enable",havingValue="true")
	public SignerProvider bouncyDsaSigner() {
		return new BouncyDsaSigner();
	}

	@Bean
	@ConditionalOnProperty(name="org.summerclouds.crypt.signer.enable",havingValue="true")
	public SignerProvider eccSigner() {
		return new EccSigner();
	}

	@Bean
	@ConditionalOnProperty(name="org.summerclouds.crypt.signer.enable",havingValue="true")
	public SignerProvider javaDsaSigner() {
		return new JavaDsaSigner();
	}

	@Bean
	@ConditionalOnProperty(name="org.summerclouds.crypt.keychain.enable",havingValue="true")
	public IKeychain keychain() {
		return new DefaultKeychain();
	}

}
