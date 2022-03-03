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
import java.io.IOException;
import java.util.UUID;

import org.summerclouds.common.core.crypt.KeyEntry;
import org.summerclouds.common.core.crypt.MutableKeychainSource;
import org.summerclouds.common.core.node.MProperties;
import org.summerclouds.common.core.tool.MSystem;
import org.summerclouds.common.core.tool.MValidator;
import org.summerclouds.common.core.util.SecureString;

public class KeychainSourceFromPlainProperties extends MapMutableVaultSource {

    private boolean editable;
    private File file;
    private long fileModified;
    private boolean fileCanWrite;

    public KeychainSourceFromPlainProperties(File file, boolean editable, String name)
            throws IOException {
        this.file = file;
        this.name = name;
        this.editable = editable;
        if (file.exists()) doLoad();
    }

    @Override
    public void doLoad() throws IOException {
        entries.clear();
        MProperties prop = MProperties.load(file);
        for (String key : prop.keys()) {
            if (MValidator.isUUID(key)) {
                KeyEntry entry = new PlainEntry(prop, name);
                entries.put(UUID.fromString(name), entry);
            }
        }
        fileModified = file.lastModified();
        fileCanWrite = file.canWrite();
    }

    @Override
    public void doSave() throws IOException {
        MProperties out = new MProperties();
        for (KeyEntry entry : entries.values()) {
            out.setString(entry.getId().toString(), entry.getValue().value());
            out.setString(entry.getId() + ".name", entry.getName());
            out.setString(entry.getId() + ".type", entry.getType());
            out.setString(entry.getId() + ".desc", entry.getDescription());
        }
        out.save(file);
        fileModified = file.lastModified();
    }

    @Override
    public boolean isMemoryBased() {
        return true;
    }

    @Override
    public MutableKeychainSource getEditable() {
        if (!editable || !fileCanWrite) return null;
        return this;
    }

    @Override
    public String toString() {
        return MSystem.toString(this, name, entries.size(), file);
    }

    private class PlainEntry implements KeyEntry {

        private UUID id;
        private SecureString value;
        private String name;
        private String type;
        private String desc;

        public PlainEntry(MProperties prop, String name) {
            id = UUID.fromString(name);
            value = new SecureString(prop.getString(name, null));
            name = prop.getString(name + ".name", "");
            type = prop.getString(name + ".type", "");
            desc = prop.getString(name + ".desc", "");
        }

        @Override
        public UUID getId() {
            return id;
        }

        @Override
        public String getType() {
            return type;
        }

        @Override
        public String getDescription() {
            return desc;
        }

        @Override
        public SecureString getValue() {
            return value;
        }

        @Override
        public String getName() {
            return name;
        }
    }

    @Override
    protected void doCheckSource() {
        if (file.lastModified() != fileModified)
            try {
                doLoad();
            } catch (IOException e) {
                log().e("loading {1} failed", file, e);
            }
    }
}
