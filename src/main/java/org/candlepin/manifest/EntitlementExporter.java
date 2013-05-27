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
import org.candlepin.model.Consumer;
import org.candlepin.model.Entitlement;
import org.candlepin.model.EntitlementCurator;
import org.candlepin.policy.js.export.ExportRules;
import org.codehaus.jackson.map.ObjectMapper;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

/**
 * EntitlementExporter
 */
public class EntitlementExporter {
    private static Logger log = Logger.getLogger(EntitlementExporter.class);

    private EntitlementCurator entitlementCurator;
    private ExportRules exportRules;

    @Inject
    EntitlementExporter(EntitlementCurator entCurator, ExportRules rules) {
        entitlementCurator = entCurator;
        exportRules = rules;
    }

    void export(ObjectMapper mapper, File baseDir, Consumer consumer)
        throws IOException, ExportCreationException {

        File entCertDir = new File(baseDir.getCanonicalPath(), "entitlements");
        entCertDir.mkdir();

        for (Entitlement ent : entitlementCurator.listByConsumer(consumer)) {
            if (ent.getDirty()) {
                log.error("Entitlement " + ent.getId() + " is marked as dirty.");
                throw new ExportCreationException("Attempted to export dirty entitlements");
            }

            if (!this.exportRules.canExport(ent)) {
                if (log.isDebugEnabled()) {
                    log.debug("Skipping export of entitlement with product:  " +
                            ent.getProductId());
                }

                continue;
            }

            if (log.isDebugEnabled()) {
                log.debug("Exporting entitlement for product" + ent.getProductId());
            }
            FileWriter writer = null;
            try {
                File file = new File(entCertDir.getCanonicalPath(), ent.getId() + ".json");
                writer = new FileWriter(file);
                mapper.writeValue(writer, ent);
            }
            finally {
                if (writer != null) {
                    writer.close();
                }
            }
        }
    }
}
