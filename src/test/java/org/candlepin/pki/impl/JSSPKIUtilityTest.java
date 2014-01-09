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

import org.mozilla.jss.pkix.primitive.Name;

import org.junit.Test;

/**
 * JSSPKIUtilityTest
 */
public class JSSPKIUtilityTest {

    @Test
    public void readkey() throws Exception {
        JSSPKIUtility util = new JSSPKIUtility(null);
        Name result = util.parseDN("CN=JarJar, OU=Binks");
        assertEquals("Name parsing is not correct", "OU=Binks, CN=JarJar",
            result.getRFC1485());
    }

}
