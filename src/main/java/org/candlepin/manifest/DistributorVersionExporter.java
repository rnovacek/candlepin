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

import org.apache.log4j.Logger;
import org.candlepin.model.DistributorVersion;
import org.candlepin.model.DistributorVersionCurator;
import org.codehaus.jackson.map.ObjectMapper;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

/**
 * DistributorVersionExporter
 */
public class DistributorVersionExporter {
    private static Logger log = Logger.getLogger(DistributorVersionExporter.class);
    private DistributorVersionCurator distVerCurator;

    @Inject
    public DistributorVersionExporter(DistributorVersionCurator dvCurator) {
        distVerCurator = dvCurator;
    }
    void export(ObjectMapper mapper, File baseDir) throws IOException {

        List<DistributorVersion> versions = distVerCurator.findAll();
        if (versions == null || versions.isEmpty()) { return; }

        File distVerDir = new File(baseDir.getCanonicalPath(), "distributor_version");
        distVerDir.mkdir();

        FileWriter writer = null;
        for (DistributorVersion dv : versions) {
            if (log.isDebugEnabled()) {
                log.debug("Exporting Distributor Version" + dv.getName());
            }
            try {
                File file = new File(distVerDir.getCanonicalPath(), dv.getName() + ".json");
                writer = new FileWriter(file);
                mapper.writeValue(writer, dv);

            }
            finally {
                if (writer != null) {
                    writer.close();
                }
            }
        }
    }
}
