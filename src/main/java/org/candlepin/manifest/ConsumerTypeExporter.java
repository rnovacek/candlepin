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

import org.candlepin.model.ConsumerType;
import org.candlepin.model.ConsumerTypeCurator;
import org.codehaus.jackson.map.ObjectMapper;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

/**
 * ConsumerTypeExporter
 */
public class ConsumerTypeExporter {
    private ConsumerTypeCurator consumerTypeCurator;

    @Inject
    ConsumerTypeExporter(ConsumerTypeCurator curator) {
        consumerTypeCurator = curator;
    }

    void export(ObjectMapper mapper, File baseDir)
        throws IOException {
        File typeDir = new File(baseDir.getCanonicalPath(), "consumer_types");
        typeDir.mkdir();

        for (ConsumerType type : consumerTypeCurator.listAll()) {
            File file = new File(typeDir.getCanonicalPath(), type.getLabel() + ".json");
            FileWriter writer = new FileWriter(file);
            mapper.writeValue(writer, type);
            writer.close();
        }
    }
}
