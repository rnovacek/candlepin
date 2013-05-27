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

import org.candlepin.auth.Principal;
import org.candlepin.config.Config;
import org.candlepin.guice.PrincipalProvider;
import org.candlepin.test.TestUtil;
import org.codehaus.jackson.map.ObjectMapper;
import org.junit.Test;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringWriter;
import java.util.Date;
import java.util.HashMap;

/**
 * MetaExporterTest
 */
public class MetaExporterTest {

    @Test
    public void testMetaExporter() throws IOException {
        File baseDir = new File("/tmp/");

        ObjectMapper mapper = SyncUtils.getObjectMapper(
            new Config(new HashMap<String, String>()));

        PrincipalProvider pprov = mock(PrincipalProvider.class);
        Principal principal = mock(Principal.class);
        when(pprov.get()).thenReturn(principal);
        when(principal.getPrincipalName()).thenReturn("myUsername");
        MetaExporter metaEx = new MetaExporter(pprov);
        StringWriter writer = new StringWriter();
        Meta meta = new Meta();
        Date now = new Date();
        String nowString = mapper.convertValue(now, String.class);
        meta.setVersion("0.1.0");
        meta.setCreated(now);

        metaEx.export(mapper, baseDir, "webapp_prefix");

        FileReader fr = new FileReader(new File("/tmp/meta.json"));
        BufferedReader br = new BufferedReader(fr);
        StringBuffer buf = new StringBuffer();
        String line;
        while ((line = br.readLine()) != null) {
            buf.append(line);
        }
        br.close();
        System.out.println(buf.toString());
        StringBuffer json = new StringBuffer();
        json.append("{\"version\":\"0.1.0\",\"created\":\"").append(nowString);
        json.append("\",\"principalName\":\"myUsername\",");
        json.append("\"webAppPrefix\":\"webapp_prefix\"}");
        assertTrue(TestUtil.isJsonEqual(json.toString(), buf.toString()));
    }

}
