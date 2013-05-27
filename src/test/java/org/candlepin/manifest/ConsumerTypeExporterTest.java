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

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.candlepin.config.Config;
import org.candlepin.model.ConsumerType;
import org.candlepin.model.ConsumerTypeCurator;
import org.candlepin.test.TestUtil;
import org.codehaus.jackson.map.ObjectMapper;
import org.junit.Test;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
/**
 * ConsumerTypeExporterTest
 */
public class ConsumerTypeExporterTest {

    @Test
    public void testConsumerTypeExport() throws IOException {
        File f = new File("/tmp/");

        ObjectMapper mapper = SyncUtils.getObjectMapper(
            new Config(new HashMap<String, String>()));

        ConsumerTypeCurator curator = mock(ConsumerTypeCurator.class);

        ConsumerTypeExporter consumerType = new ConsumerTypeExporter(curator);
        when(curator.listAll()).thenReturn(new ArrayList<ConsumerType>() {
            {
                add(new ConsumerType("TESTTYPE"));
            }
        });

        consumerType.export(mapper, f);

        FileReader fr = new FileReader(new File("/tmp/consumer_types/TESTTYPE.json"));
        BufferedReader br = new BufferedReader(fr);
        StringBuffer buf = new StringBuffer();
        String line;
        while ((line = br.readLine()) != null) {
            buf.append(line);
        }
        br.close();

        StringBuffer json = new StringBuffer();
        json.append("{\"id\":null,\"label\":\"TESTTYPE\",");
        json.append("\"manifest\":false}");
        assertTrue(TestUtil.isJsonEqual(json.toString(), buf.toString()));
    }


}
