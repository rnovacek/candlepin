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
package org.candlepin.pki.impl;

import static org.junit.Assert.*;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.mock;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import org.mockito.Mock;
import org.mozilla.jss.pkix.primitive.Name;
import org.candlepin.config.Config;
import org.candlepin.config.ConfigProperties;
import org.candlepin.pki.PKIReader;
import org.candlepin.pki.PEMEncoder;
import org.candlepin.pki.X509CRLEntryWrapper;
import org.candlepin.test.TestUtil;
import org.candlepin.util.CrlFileUtil;
import org.junit.Before;
import org.junit.Test;

/**
 * JSSPKIUtilityTest
 */
public class JSSPKIUtilityTest {

    private static final KeyPair KP = TestUtil.generateKP();
    private static final X509Certificate CERT = TestUtil.generateCertificate(KP);

    private Config config;
    private JSSPKIUtility pkiUtility;
    @Mock private PKIReader pkiReader;

    @Before
    public void before() throws Exception {
        this.config = new ConfigForTesting();
        pkiReader = mock(PKIReader.class);
        when(pkiReader.getCaKey()).thenReturn(KP.getPrivate());
        when(pkiReader.getCACert()).thenReturn(CERT);
        pkiUtility = new JSSPKIUtility(null, config, new CrlFileUtil(new PEMEncoder()));
    }

    @Test
    public void readkey() throws Exception {
        Name result = pkiUtility.parseDN("CN=JarJar, OU=Binks");
        assertEquals("Name parsing is not correct", "OU=Binks, CN=JarJar",
            result.getRFC1485());
    }

    @Test
    public void generateCrl() throws Exception {
        BigInteger serial1 = new BigInteger("2233");
        BigInteger serial2 = new BigInteger("2234");
        List<X509CRLEntryWrapper> entries = new LinkedList<X509CRLEntryWrapper>();
        entries.add(new X509CRLEntryWrapper(serial1, new Date()));
        entries.add(new X509CRLEntryWrapper(serial2, new Date()));
        X509CRL crl = pkiUtility.createX509CRL(entries, new BigInteger("1"));

        X509CRLEntry crlEntry1 = crl.getRevokedCertificate(
            entries.get(0).getSerialNumber());
        assertNotNull(crlEntry1);
        assertEquals(serial1, crlEntry1.getSerialNumber());

        X509CRLEntry crlEntry2 = crl.getRevokedCertificate(
            entries.get(1).getSerialNumber());
        assertNotNull(crlEntry2);
        assertEquals(serial2, crlEntry2.getSerialNumber());
    }

    private static class ConfigForTesting extends Config {
        public ConfigForTesting() {
            super(ConfigProperties.DEFAULT_PROPERTIES);
            configuration.put(ConfigProperties.CRL_WORK_DIR, "/tmp/");
        }
    }
}
