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

import org.candlepin.model.Consumer;
import org.candlepin.model.IdentityCertificate;
import org.codehaus.jackson.map.ObjectMapper;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

/**
 * IdentityCertificateExporter
 */
public class IdentityCertificateExporter {
    @Inject
    IdentityCertificateExporter() {
    }

    void export(ObjectMapper mapper, File baseDir, Consumer consumer) throws IOException {
        File idcertdir = new File(baseDir.getCanonicalPath(), "upstream_consumer");
        idcertdir.mkdir();

        IdentityCertificate cert = consumer.getIdCert();
        File file = new File(idcertdir.getCanonicalPath(),
            cert.getSerial().getId() + ".json");

        // paradigm dictates this should go in an exporter.export method
        FileWriter writer = null;

        try {
            writer = new FileWriter(file);
            mapper.writeValue(writer, cert);
        }
        finally {
            if (writer != null) {
                writer.close();
            }
        }
    }
}
