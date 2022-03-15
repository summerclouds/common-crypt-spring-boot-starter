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
