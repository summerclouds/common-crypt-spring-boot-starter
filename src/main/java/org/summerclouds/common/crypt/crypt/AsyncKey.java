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

import java.math.BigInteger;

import org.summerclouds.common.core.tool.MSystem;

public class AsyncKey {
    private BigInteger modulus;
    private BigInteger publicExponent;
    private BigInteger privateExponent;
    private BigInteger prime1;
    private BigInteger prime2;
    private BigInteger exponent1;
    private BigInteger exponent2;
    private BigInteger coefficient;
    private int maxLoad = -1;

    public AsyncKey() {}

    public AsyncKey(
            BigInteger modulus,
            BigInteger publicExponent,
            BigInteger privateExponent,
            BigInteger prime1,
            BigInteger prime2,
            BigInteger exponent1,
            BigInteger exponent2,
            BigInteger coefficient,
            int maxLoad) {
        super();
        this.modulus = modulus;
        this.publicExponent = publicExponent;
        this.privateExponent = privateExponent;
        this.prime1 = prime1;
        this.prime2 = prime2;
        this.exponent1 = exponent1;
        this.exponent2 = exponent2;
        this.coefficient = coefficient;
        this.maxLoad = maxLoad;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    protected void setModulus(BigInteger modulus) {
        this.modulus = modulus;
    }

    public BigInteger getPublicExponent() {
        return publicExponent;
    }

    protected void setPublicExponent(BigInteger publicExponent) {
        this.publicExponent = publicExponent;
    }

    public BigInteger getPrivateExponent() {
        return privateExponent;
    }

    protected void setPrivateExponent(BigInteger privateExponent) {
        this.privateExponent = privateExponent;
    }

    public BigInteger getPrime1() {
        return prime1;
    }

    protected void setPrime1(BigInteger prime1) {
        this.prime1 = prime1;
    }

    public BigInteger getPrime2() {
        return prime2;
    }

    protected void setPrime2(BigInteger prime2) {
        this.prime2 = prime2;
    }

    public BigInteger getExponent1() {
        return exponent1;
    }

    protected void setExponent1(BigInteger exponent1) {
        this.exponent1 = exponent1;
    }

    public BigInteger getExponent2() {
        return exponent2;
    }

    protected void setExponent2(BigInteger exponent2) {
        this.exponent2 = exponent2;
    }

    public BigInteger getCoefficient() {
        return coefficient;
    }

    protected void setCoefficient(BigInteger coefficient) {
        this.coefficient = coefficient;
    }

    public int getMaxLoad() {
        return maxLoad;
    }

    @Override
    public String toString() {
        return MSystem.toString(this, publicExponent, modulus);
    }
}
