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

import org.summerclouds.common.core.cfg.CfgBoolean;
import org.summerclouds.common.core.log.MLog;
import org.summerclouds.common.core.tool.MKeychain.KeychainSource;

import de.mhus.lib.core.MApi;
import de.mhus.lib.core.cfg.CfgFile;

public class DefaultVaultSourceFactory extends MLog implements KeychainSourceFactory {

    private static CfgFile CFG_DEFAULT_FILE =
            new CfgFile(
                    MKeychain.class,
                    "file",
                    MApi.getFile(MApi.SCOPE.ETC, "de.mhus.lib.core.vault.FileVaultSource.dat"));
    private static CfgFile CFG_DEFAULT_FOLDER =
            new CfgFile(
                    MKeychain.class,
                    "folder",
                    MApi.getFile(MApi.SCOPE.DATA, "de.mhus.lib.core.vault.FolderVaultSource"));
    private static CfgBoolean CFG_EDITABLE =
            new CfgBoolean(KeychainSourceFromPlainProperties.class, "editable", false);

    @Override
    public KeychainSource create(String name, KeychainPassphrase vaultPassphrase) {
        KeychainSource def = null;
        if (MKeychain.SOURCE_DEFAULT.equals(name)) {
            if (CFG_DEFAULT_FILE.value().exists()) {

                if (CFG_DEFAULT_FILE.value().getName().endsWith(".json")) {
                    try {
                        def =
                                new KeychainSourceFromPlainJson(
                                        CFG_DEFAULT_FILE.value(), CFG_EDITABLE.value(), name);
                    } catch (IOException e) {
                        log().d(e);
                    }
                } else if (CFG_DEFAULT_FILE.value().getName().endsWith(".properties")) {
                    try {
                        def =
                                new KeychainSourceFromPlainProperties(
                                        CFG_DEFAULT_FILE.value(), CFG_EDITABLE.value(), name);
                    } catch (IOException e) {
                        log().d(e);
                    }
                } else {
                    // legacy
                    try {
                        def =
                                new KeychainSourceFromSecFile(
                                        CFG_DEFAULT_FILE.value(),
                                        vaultPassphrase.getPassphrase(),
                                        name);
                    } catch (IOException e) {
                        log().d(e);
                    }
                }
            } else {
                // default
                try {
                    def =
                            new KeychainSourceFromSecFolder(
                                    CFG_DEFAULT_FOLDER.value(),
                                    vaultPassphrase.getPassphrase(),
                                    name);
                } catch (IOException e) {
                    log().w(e);
                }
            }
        } else {
            File file = new File(name);
            if (file.exists() && file.isFile()) {
                try {
                    def =
                            new KeychainSourceFromSecFile(
                                    file, vaultPassphrase.getPassphrase(), file.getName());
                } catch (IOException e) {
                    log().d(e);
                }
            } else {
                try {
                    def =
                            new KeychainSourceFromSecFolder(
                                    file, vaultPassphrase.getPassphrase(), file.getName());
                } catch (IOException e) {
                    log().w(e);
                }
            }
        }
        return def;
    }
}
