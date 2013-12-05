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

import org.candlepin.config.Config;
import org.candlepin.config.ConfigProperties;
import org.junit.Test;

import java.security.cert.CertificateException;
import java.util.HashMap;


/**
 * JSSPKIReaderTest
 */
public class JSSPKIReaderTest {

    @Test
    public void readkey() throws CertificateException {
        Config config = new Config(
            new HashMap<String, String>() {
                {
                    put(ConfigProperties.CA_ALIAS,
                        "tomcat");
                    put(ConfigProperties.CA_TOKEN_PREFIX,
                        "NSS system database:");
                }
            });
        new JSSPKIReader(config);
    }

}
