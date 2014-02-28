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
import org.candlepin.pki.PKIReader;
import org.candlepin.util.Util;

import com.google.inject.Inject;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PasswordFinder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Set;

/**
 * The default {@link PKIReader} for Candlepin.  This reads the file paths for
 * the CA certificate and CA private key, as well as an optional password, from
 * the config system.  These values are customizable via /etc/candlepin/candlepin.conf.
 *
 * All code that imports bouncycastle should live either in this module,
 * or in {@link BouncyCastlePKIUtility}
 *
 * (March 24, 2011) Notes on implementing a PKIReader with NSS/JSS:
 *
 * The only code here that's bouncycastle specific is the PEMReader.
 * JSS doesn't provide any code for reading/writing PEM, so we'd need to read the input
 * file, parse the headers related to private key storage (to make sure we have the right
 * file type and determine if we have to decrypt with a password), base64 decode the input
 * into DER, optionally decrypt, then build an RSAKeySpec and pass it on to java's
 * keyfactory to get a key.
 *
 * As of March 24, 2011, we're only using bouncycastle to read and write encodings, not
 * perform any "real" crypto work. if we tell the PEMReader to use a different JSSE
 * provider (say, SunJSSE), and don't load the bouncycastle provider, we're not technically
 * using bouncycastle for crypto. We could also take only the subset of classes we require
 * (none of the crypto ones) and use those.
 *
 * See also {@link BouncyCastlePKIUtility} for more notes.
 */
public class BouncyCastlePKIReader extends PKIReader implements PasswordFinder {
    private static Logger log = LoggerFactory.getLogger(BouncyCastlePKIReader.class);

    private CertificateFactory certFactory;
    private String caCertPath;
    private String upstreamCaCertPath;
    private String caKeyPath;
    private String caKeyPassword;
    private final X509Certificate x509Certificate;
    private final Set<X509Certificate> upstreamX509Certificates;
    private final PrivateKey privateKey;

    // Don't even load the web app if we can't find BouncyCastle
    static {
        try {
            Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
        }
        catch (ClassNotFoundException e) {
            log.error("Could not find BouncyCastleProvider", e);
            throw new IllegalStateException("Could not find BouncyCastleProvider", e);
        }
    }

    @Inject
    public BouncyCastlePKIReader(Config config) throws CertificateException {
        log.error("BC at {}", Security.addProvider(new BouncyCastleProvider()));
        certFactory = CertificateFactory.getInstance("X.509");
        this.caCertPath = config.getString(ConfigProperties.CA_CERT);
        this.upstreamCaCertPath = config.getString(ConfigProperties.CA_CERT_UPSTREAM);
        this.caKeyPath = config.getString(ConfigProperties.CA_KEY);
        Util.assertNotNull(this.caCertPath,
            "caCertPath cannot be null. Unable to load CA Certificate");
        Util.assertNotNull(this.caKeyPath,
            "caKeyPath cannot be null. Unable to load PrivateKey");
        this.caKeyPassword = config.getString(ConfigProperties.CA_KEY_PASSWORD);
        this.x509Certificate = loadCACertificate(this.caCertPath);
        this.upstreamX509Certificates = loadUpstreamCACertificates(upstreamCaCertPath);
        this.privateKey = loadPrivateKey();
    }

    protected CertificateFactory getCertFactory() {
        return certFactory;
    }

    /**
     * @return
     */
    private PrivateKey loadPrivateKey() {
        try {
            InputStreamReader inStream = new InputStreamReader(
                new FileInputStream(this.caKeyPath));
            PEMReader reader = null;

            try {
                if (this.caKeyPassword != null) {
                    reader = new PEMReader(inStream, this);
                }
                else {
                    reader = new PEMReader(inStream);
                }

                KeyPair caKeyPair = (KeyPair) reader.readObject();
                if (caKeyPair == null) {
                    throw new GeneralSecurityException(
                        "Reading CA private key failed");
                }
                return caKeyPair.getPrivate();
            }
            finally {
                reader.close();
            }
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public X509Certificate getCACert() throws IOException, CertificateException {
        return this.x509Certificate;
    }

    @Override
    public Set<X509Certificate> getUpstreamCACerts()
        throws IOException, CertificateException {
        return this.upstreamX509Certificates;
    }

    /**
     * {@inheritDoc}
     *
     * Reads the {@link KeyPair} from the CA's private key file specified in the
     * candlepin config.
     *
     * @return private key for the CA cert
     */
    @Override
    public PrivateKey getCAKey() throws IOException, GeneralSecurityException {
        return this.privateKey;
    }

    @Override
    public char[] getPassword() {
        // just grab the key password that was pulled from the config
        return caKeyPassword.toCharArray();
    }

}
