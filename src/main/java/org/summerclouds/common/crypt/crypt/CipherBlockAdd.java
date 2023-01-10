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
package org.summerclouds.common.crypt.crypt;

import org.summerclouds.common.core.tool.MMath;

/**
 * add for encode and sub for decode current block value.
 *
 * @author mikehummel
 */
public class CipherBlockAdd implements CipherBlock {

    private byte[] block;
    private int pos;

    public CipherBlockAdd(byte[] block) {
        this.block = block;
    }

    public CipherBlockAdd(int size) {
        block = new byte[size];
    }

    public byte[] getBlock() {
        return block;
    }

    public int getSize() {
        return block.length;
    }

    @Override
    public void reset() {
        pos = 0;
    }

    @Override
    public byte encode(byte in) {
        in = MMath.addRotate(in, block[pos]);
        next();
        return in;
    }

    @Override
    public byte decode(byte in) {
        in = MMath.subRotate(in, block[pos]);
        next();
        return in;
    }

    private void next() {
        pos = (pos + 1) % block.length;
    }
}
