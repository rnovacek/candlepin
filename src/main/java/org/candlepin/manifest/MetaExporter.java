/**
 * Copyright (c) 2009 - 2012 Red Hat, Inc.
 *
 * This software is licensed to you under the GNU General Public License,
 * version 2 (GPLv2). There is NO WARRANTY for this software, express or
 * implied, including the implied warranties of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
 * along with this software; if not, see
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 *
 * Red Hat trademarks are not licensed under GPLv2. No permission is
 * granted to use or replicate Red Hat trademarks that are incorporated
 * in this software or its documentation.
 */
package org.candlepin.manifest;

import com.google.inject.Inject;

import org.candlepin.guice.PrincipalProvider;
import org.candlepin.util.VersionUtil;
import org.codehaus.jackson.map.ObjectMapper;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Date;
import java.util.Map;

/**
 * Meta maps to meta.json in the export
 *
 */
public class MetaExporter {
    private PrincipalProvider principalProvider;

    @Inject
    MetaExporter(PrincipalProvider provider) {
        principalProvider = provider;
    }

    void export(ObjectMapper mapper, File baseDir, String url) throws IOException {
        File file = new File(baseDir.getCanonicalPath(), "meta.json");
        FileWriter writer = new FileWriter(file);
        Meta m = new Meta(getVersion(), new Date(),
            principalProvider.get().getPrincipalName(),
            url);
        mapper.writeValue(writer, m);
        writer.close();
    }

    private String getVersion() {
        Map<String, String> map = VersionUtil.getVersionMap();
        return map.get("version") + "-" + map.get("release");
    }

}
