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

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import org.codehaus.jackson.map.ObjectMapper;
import org.candlepin.model.Consumer;

import com.google.inject.Inject;

/**
 * Consumer - maps to the consumer.json file
 */
public class ConsumerExporter {

    @Inject
    ConsumerExporter() {
    }

    void export(ObjectMapper mapper, File baseDir, Consumer consumer,
        String weburl, String apiurl) throws IOException {
        ConsumerDto dto = new ConsumerDto(consumer.getUuid(), consumer.getName(),
            consumer.getType(), consumer.getOwner(), weburl, apiurl);
        File file = new File(baseDir.getCanonicalPath(), "consumer.json");
        FileWriter writer = new FileWriter(file);
        mapper.writeValue(writer, dto);
        writer.close();
    }
}
