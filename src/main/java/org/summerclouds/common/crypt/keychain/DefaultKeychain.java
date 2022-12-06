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

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.annotation.PostConstruct;

import org.summerclouds.common.core.M;
import org.summerclouds.common.core.crypt.IKeychain;
import org.summerclouds.common.core.crypt.KeyEntry;
import org.summerclouds.common.core.crypt.KeychainSource;
import org.summerclouds.common.core.lang.SummerApplicationLifecycle;
import org.summerclouds.common.core.log.MLog;
import org.summerclouds.common.core.tool.MKeychain;
import org.summerclouds.common.core.tool.MSpring;

public class DefaultKeychain extends MLog implements IKeychain, SummerApplicationLifecycle {

    private HashMap<String, KeychainSource> sources = new HashMap<>();
    private IKeychain parent;


    protected void setup() {
    	Map<String, KeychainSource> map = MSpring.getBeansOfType(KeychainSource.class);
    	for (KeychainSource source : map.values())
    		sources.put(source.getName(), source);
    	checkDefaults();
    }
    
    public DefaultKeychain() {
    	this(null);
    }

    public DefaultKeychain(IKeychain parent) {
        this.parent = parent;
        checkDefaults();
    }

    @Override
    public void registerSource(KeychainSource source) {
        if (source == null) return;
        synchronized (sources) {
            sources.put(source.getName(), source);
        }
    }

    @Override
    public void unregisterSource(String sourceName) {
        if (sourceName == null) return;
        synchronized (sources) {
            sources.remove(sourceName);
        }
    }

    @Override
    public String[] getSourceNames() {
        if (parent != null) {
            String[] parentNames = parent.getSourceNames();
            synchronized (sources) {
                String[] out = new String[parentNames.length + sources.size()];
                int cnt = 0;
                for (String name : sources.keySet()) {
                    out[cnt] = name;
                    cnt++;
                }
                for (String name : parentNames) {
                    out[cnt] = name;
                    cnt++;
                }
                return out;
            }
        }
        synchronized (sources) {
            return sources.keySet().toArray(new String[sources.size()]);
        }
    }

    @Override
    public KeychainSource getSource(String name) {
        if (name == null) return null;
        synchronized (sources) {
            KeychainSource ret = sources.get(name);
            if (ret == null && parent != null) return parent.getSource(name);
            else return ret;
        }
    }

    @Override
    public KeyEntry getEntry(UUID id) {
        if (id == null) return null;
        synchronized (sources) {
            for (KeychainSource source : sources.values()) {
                KeyEntry res = source.getEntry(id);
                if (res != null) return res;
            }
        }
        if (parent != null) return parent.getEntry(id);
        return null;
    }

    @Override
    public KeyEntry getEntry(String name) {
        if (name == null) return null;
        synchronized (sources) {
            for (KeychainSource source : sources.values()) {
                KeyEntry res = source.getEntry(name);
                if (res != null) return res;
            }
        }
        if (parent != null) return parent.getEntry(name);
        return null;
    }
    
    void checkDefaults() {
        KeychainSource def = getSource(MKeychain.SOURCE_DEFAULT);
        if (def == null) {

            KeychainPassphrase vaultPassphrase = M.l(KeychainPassphrase.class);
            KeychainSourceFactory factory = M.l(KeychainSourceFactory.class);

            def = factory.create(MKeychain.SOURCE_DEFAULT, vaultPassphrase);
            if (def != null) registerSource(def);
        }
    }

    @Override
    public void onSummerApplicationStart() throws Exception {
        setup();
    }

    @Override
    public void onSummerApplicationStop() throws Exception {

    }
}
