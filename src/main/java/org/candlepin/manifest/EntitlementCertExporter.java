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
import org.candlepin.model.EntitlementCertificate;
import org.candlepin.policy.js.export.ExportRules;
import org.candlepin.service.EntitlementCertServiceAdapter;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Set;

/**
 * EntitlementCertExporter
 */
public class EntitlementCertExporter {
    private static Logger log = Logger.getLogger(EntitlementCertExporter.class);
    private EntitlementCertServiceAdapter entCertAdapter;
    private ExportRules exportRules;

    @Inject
    EntitlementCertExporter(ExportRules rules, EntitlementCertServiceAdapter adapter) {
        exportRules = rules;
        entCertAdapter = adapter;
    }

    void export(File baseDir, Consumer consumer, Set<Long> serials, boolean manifest)
        throws IOException {

        File entCertDir = new File(baseDir.getCanonicalPath(), "entitlement_certificates");
        entCertDir.mkdir();

        for (EntitlementCertificate cert : entCertAdapter.listForConsumer(consumer)) {
            if (manifest && !this.exportRules.canExport(cert.getEntitlement())) {
                if (log.isDebugEnabled()) {
                    log.debug("Skipping export of entitlement cert with product:  " +
                            cert.getEntitlement().getProductId());
                }
                continue;
            }

            if ((serials == null) || (serials.contains(cert.getSerial().getId()))) {
                log.debug("Exporting entitlement certificate: " + cert.getSerial());
                File file = new File(entCertDir.getCanonicalPath(),
                    cert.getSerial().getId() + ".pem");
                FileWriter writer = new FileWriter(file);
                writer.write(cert.getCert());
                writer.write(cert.getKey());
                writer.close();
            }
        }
    }
}
