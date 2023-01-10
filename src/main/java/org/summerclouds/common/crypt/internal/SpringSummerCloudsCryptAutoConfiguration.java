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
    @ConditionalOnProperty(name = "org.summerclouds.crypt.cipher.enabled", havingValue = "true")
    public CipherProvider bouncyAesWithRsaCipher() {
        return new BouncyAesWithRsaCipher();
    }

    @Bean
    @ConditionalOnProperty(name = "org.summerclouds.crypt.cipher.enabled", havingValue = "true")
    public CipherProvider bouncyRsaCipher() {
        return new BouncyRsaCipher();
    }

    @Bean
    @ConditionalOnProperty(name = "org.summerclouds.crypt.cipher.enabled", havingValue = "true")
    public CipherProvider javaAesCipher() {
        return new JavaAesCipher();
    }

    @Bean
    @ConditionalOnProperty(name = "org.summerclouds.crypt.cipher.enabled", havingValue = "true")
    public CipherProvider javaAesWithRsaCipher() {
        return new JavaAesWithRsaCipher();
    }

    @Bean
    @ConditionalOnProperty(name = "org.summerclouds.crypt.cipher.enabled", havingValue = "true")
    public CipherProvider javaRsaCipher() {
        return new JavaRsaCipher();
    }

    @Bean
    @ConditionalOnProperty(name = "org.summerclouds.crypt.signer.enabled", havingValue = "true")
    public SignerProvider bouncyDsaSigner() {
        return new BouncyDsaSigner();
    }

    @Bean
    @ConditionalOnProperty(name = "org.summerclouds.crypt.signer.enabled", havingValue = "true")
    public SignerProvider eccSigner() {
        return new EccSigner();
    }

    @Bean
    @ConditionalOnProperty(name = "org.summerclouds.crypt.signer.enabled", havingValue = "true")
    public SignerProvider javaDsaSigner() {
        return new JavaDsaSigner();
    }

    @Bean
    @ConditionalOnProperty(name = "org.summerclouds.crypt.keychain.enabled", havingValue = "true")
    public IKeychain keychain() {
        return new DefaultKeychain();
    }
}
