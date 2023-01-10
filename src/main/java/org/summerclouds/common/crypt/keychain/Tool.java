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
package org.summerclouds.common.crypt.keychain;

import java.io.File;
import java.io.IOException;
import java.util.UUID;

import org.summerclouds.common.core.console.ConsoleTable;
import org.summerclouds.common.core.crypt.KeyEntry;
import org.summerclouds.common.core.crypt.KeychainSource;
import org.summerclouds.common.core.tool.MKeychain;
import org.summerclouds.common.core.util.MArgs;

public class Tool {

    public static void main(String[] in) throws IOException {
        MArgs args =
                new MArgs(
                        in,
                        MArgs.opt('f', "file", 1, false, "File"),
                        MArgs.opt('p', "passphrase", 1, false, "Passphrase"));
        if (!args.isPrintUsage()) {
            args.printUsage();
            System.exit(args.isValid() ? 0 : 1);
        }

        KeychainSource source = null;
        if (args.hasOption("file")) {
            String vp = args.getOption("p").getValue("setit");
            File f = new File(args.getOption("file").getValue());
            source = new KeychainSourceFromSecFile(f, vp);
            MKeychain.registerSource(source);
        }
        if (source == null) source = MKeychain.getSource(MKeychain.SOURCE_DEFAULT);

        String cmd = args.getArgument(1).getValue();

        switch (cmd) {
            case "help":
                {
                    System.out.println("Usage: <cmd> <args>");
                    System.out.println("list - list all keys");
                }
                break;
            case "list":
                {
                    ConsoleTable out = new ConsoleTable();
                    out.setHeaderValues("Source", "Id", "Type", "Description");
                    for (String sourceName : MKeychain.getSourceNames()) {
                        source = MKeychain.getSource(sourceName);
                        for (UUID id : source.getEntryIds()) {
                            KeyEntry entry = source.getEntry(id);
                            out.addRowValues(
                                    sourceName, id, entry.getType(), entry.getDescription());
                        }
                    }
                    out.print();
                }
                break;
        }
    }
}
