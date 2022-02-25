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
package org.summerclouds.common.crypt.keychain;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.util.UUID;

import org.summerclouds.common.core.error.MException;
import org.summerclouds.common.core.tool.MKeychain.KeyEntry;
import org.summerclouds.common.core.tool.MKeychain.MutableVaultSource;
import org.summerclouds.common.core.tool.MSystem;
import org.summerclouds.common.core.util.SecureString;
import org.summerclouds.common.crypt.crypt.MCrypt;

public class KeychainSourceFromSecFile extends MapMutableVaultSource {

    private SecureString passphrase;
    private File file;

    public KeychainSourceFromSecFile(File file, String passphrase, String name) throws IOException {
        this(file, passphrase);
        this.name = name;
    }

    public KeychainSourceFromSecFile(File file, String passphrase) throws IOException {
        this.passphrase = new SecureString(passphrase);
        this.file = file;
        if (file.exists()) doLoad();
    }

    @Override
    public void doLoad() throws IOException {
        FileInputStream parent = new FileInputStream(file);
        InputStream is = MCrypt.createCipherInputStream(parent, passphrase.value());
        ObjectInputStream ois = new ObjectInputStream(is);
        name = ois.readUTF();
        int size = ois.readInt();
        entries.clear();
        for (int i = 0; i < size; i++) {
            KeyEntry entry = new FileEntry(ois);
            try {
                addEntry(entry);
            } catch (MException e) {
                log().d("add entry {1} failed", entry, e);
            }
        }
        parent.close();
    }

    @Override
    public void doSave() throws IOException {
        FileOutputStream parent = new FileOutputStream(file);
        OutputStream os = MCrypt.createCipherOutputStream(parent, passphrase.value());
        ObjectOutputStream oos = new ObjectOutputStream(os);
        oos.writeInt(1); // version
        oos.writeUTF(name);
        oos.writeInt(entries.size());
        for (KeyEntry entry : entries.values()) {
            oos.writeUTF(entry.getId().toString());
            oos.writeUTF(entry.getType());
            oos.writeUTF(entry.getDescription());
            oos.writeObject(entry.getValue());
        }
        oos.flush();
        parent.close();
    }

    private class FileEntry extends DefaultEntry {

        public FileEntry(ObjectInputStream ois) throws IOException {
            int v = ois.readInt();
            if (v == 1) {
                id = UUID.fromString(ois.readUTF());
                type = ois.readUTF();
                description = ois.readUTF();
                try {
                    value = (SecureString) ois.readObject();
                } catch (ClassNotFoundException e) {
                    throw new IOException(e);
                }
            }
        }
    }

    @Override
    public String toString() {
        return MSystem.toString(this, name, entries.size(), file);
    }

    @Override
    public boolean isMemoryBased() {
        return true;
    }

    @Override
    public MutableVaultSource getEditable() {
        return this;
    }

    @Override
    protected void doCheckSource() {}
}
