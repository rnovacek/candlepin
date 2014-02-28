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

import static junit.framework.Assert.assertEquals;

import org.candlepin.config.Config;
import org.candlepin.config.ConfigProperties;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mozilla.jss.CertDatabaseException;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.CryptoManager.InitializationValues;
import org.mozilla.jss.KeyDatabaseException;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.HashMap;
import java.util.Map;

/**
 * JSSPKIReaderTest
 */
public class JSSPKIReaderTest {
    private static Logger log = LoggerFactory.getLogger(JSSPKIReaderTest.class);

    /*
     * To build yourself a keystore:
     *   keytool -genkeypair -alias test -keysize 2048 -keyalg RSA
     *     -validity 10000 -storetype pkcs12 -keystore keystore.p12 -dname "CN=Unit Test"
     *     -storepass changeit
     *
     * To get the modulus, we must first export to PEM:
     *   openssl pkcs12 -in keystore.p12 -out keystore.pem -passin pass:changeit -nodes
     *
     * And to get the modulus:
     * echo "ibase=16;obase=A;$(openssl rsa -in keystore.pem -modulus -noout | cut -d= -f2)" | bc
     *
     * (or however else you want to convert hex to decimal)
     */

    private BigInteger expectedModulus = new BigInteger(
        "20339502404567983048813630685909938925267850614362996845098327696798" +
        "08321915770474793895589693195543349476454963801499384580429853802872" +
        "85487820741535502750225376967542228687407403559651350319409589845804" +
        "59826974903951965444363320279392056143453969219890575741640378638124" +
        "53764373012116963330780895832677402174121366318976731203899624908083" +
        "86691712447663765529391008623452230431781023135093523786278265765356" +
        "47978228676245690810849022982261104849055707958827972067448155647552" +
        "55629282706917435782661755773460197733893888678905384726199358978369" +
        "62187796831580462379009415759302975498153207467619170013690412825115" +
        "38521"
    );

    private Map<String, String> props;
    private File resourceDir = new File("target/test/resources");

    @BeforeClass
    public static void initCryptoManager() throws Exception {
        InitializationValues values = new InitializationValues("sql:/etc/pki/nssdb");
        // Do not actually install JSS as a provider.  Everything will break if you do that.
        values.installJSSProvider = false;
        CryptoManager.initialize(values);
    }

    @Before
    public void setUp() throws KeyDatabaseException,
    CertDatabaseException, AlreadyInitializedException, GeneralSecurityException {
        props = new HashMap<String, String>() {
            {
                put(ConfigProperties.CA_CERT,
                    new File(resourceDir, "certs/test.crt").getPath());
                put(ConfigProperties.CA_CERT_UPSTREAM,
                    new File(resourceDir, "certs/upstream").getPath());
            }
        };
    }

    @Test
    public void readPKCS12() throws Exception {
        props.put(ConfigProperties.CA_KEYSTORE,
            new File(resourceDir, "keys/keystore.p12").getPath());
        props.put(ConfigProperties.CA_KEYSTORE_PASSWORD_FILE,
            new File(resourceDir, "keys/keystore-password.txt").getPath());
        props.put(ConfigProperties.CA_KEYSTORE_NICKNAME, "test");

        Config config = new Config(props);
        JSSPKIReader reader = new JSSPKIReader(config, CryptoManager.getInstance());
        PrivateKey key = reader.getCaKey();
        assertEquals("RSA", key.getAlgorithm());
        RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) key;
        assertEquals(expectedModulus, rsaKey.getModulus());
    }

    @Test(expected = GeneralSecurityException.class)
    public void missingNickname() throws Exception {
        props.put(ConfigProperties.CA_KEYSTORE,
            new File(resourceDir, "keys/keystore.p12").getPath());
        props.put(ConfigProperties.CA_KEYSTORE_PASSWORD_FILE,
            new File(resourceDir, "keys/keystore-password.txt").getPath());
        props.put(ConfigProperties.CA_KEYSTORE_NICKNAME, "missing");

        Config config = new Config(props);
        JSSPKIReader reader = new JSSPKIReader(config, CryptoManager.getInstance());
    }

    @Test(expected = GeneralSecurityException.class)
    public void bassPassword() throws Exception {
        props.put(ConfigProperties.CA_KEYSTORE,
            new File(resourceDir, "keys/keystore.p12").getPath());
        props.put(ConfigProperties.CA_KEYSTORE_PASSWORD_FILE,
            new File(resourceDir, "keys/keystore-password-bad.txt").getPath());
        props.put(ConfigProperties.CA_KEYSTORE_NICKNAME, "test");

        Config config = new Config(props);
        JSSPKIReader reader = new JSSPKIReader(config, CryptoManager.getInstance());
    }
}
