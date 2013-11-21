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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import org.apache.log4j.Logger;
import org.candlepin.config.Config;
import org.candlepin.config.ConfigProperties;
import org.candlepin.pki.PKIReader;
import org.candlepin.util.Util;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.CryptoManager.NotInitializedException;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.util.Password;
import org.mozilla.jss.util.PasswordCallback;
import org.mozilla.jss.util.PasswordCallbackInfo;

import com.google.inject.Inject;

/**
 * DefaultPKIReader. This reads a java keystore in PKCS12 format. The private
 * key and CA certificate are extracted from the keystore and used by the
 * utility to generate certificates
 */
public class JSSPKIReader implements PKIReader {

    private static Logger log = Logger.getLogger(JSSPKIReader.class);

    private CertificateFactory certFactory;
    // Location for upstream certificates
    private String upstreamCaCertPath;
    // Password to unlock the private key
    private String caKeyPassword;
    private String caKeyTokenPrefix;
    // The name (alias) the key is stored under.
    private String pKeyAlias;
    private PrivateKey pKey;
    private X509Certificate caCert;
    private Set<X509Certificate> upstreamX509Certificates;
    private CryptoManager cryptoManager;

    static {
        try {
            CryptoManager.initialize("sql:/etc/pki/nssdb");
        }
        catch (Exception e) {
            log.error("Exception during itialization", e);
        }
    }

    @Inject
    public JSSPKIReader(Config config) throws CertificateException {

        try {
            this.cryptoManager = CryptoManager.getInstance();
            this.cryptoManager.setPasswordCallback(new JSSPasswordCallback());
            log.info("FIPS status is " + cryptoManager.FIPSEnabled());
            certFactory = CertificateFactory.getInstance("X.509");
        }
        catch (NotInitializedException e) {
            log.error("Crypto Manager not initialized", e);
            throw new CertificateException(e);
        }

        this.upstreamCaCertPath = config
            .getString(ConfigProperties.CA_CERT_UPSTREAM);
        log.debug("Using caCertPath " + this.upstreamCaCertPath);
        this.pKeyAlias = config.getString(ConfigProperties.CA_ALIAS);
        log.debug("Using key alias " + this.pKeyAlias);
        Util.assertNotNull(this.pKeyAlias,
            "pKeyAlias cannot be null. Unable to load CA Certificate");
        this.caKeyTokenPrefix = config
            .getString(ConfigProperties.CA_TOKEN_PREFIX);
        this.caKeyPassword = config.getString(ConfigProperties.CA_KEY_PASSWORD);
        this.upstreamX509Certificates = this
            .loadUpstreamCACertificates(this.upstreamCaCertPath);
        this.loadCA();
    }

    /*
     * (non-Javadoc)
     * @see org.candlepin.pki.PKIReader#getCACert()
     */
    @Override
    public X509Certificate getCACert() throws IOException, CertificateException {
        return this.caCert;
    }

    /*
     * (non-Javadoc)
     * @see org.candlepin.pki.PKIReader#getUpstreamCACerts()
     */
    @Override
    public Set<X509Certificate> getUpstreamCACerts() throws IOException,
        CertificateException {
        return this.upstreamX509Certificates;
    }

    /*
     * (non-Javadoc)
     * @see org.candlepin.pki.PKIReader#getCaKey()
     */
    @Override
    public PrivateKey getCaKey() throws IOException, GeneralSecurityException {
        return this.pKey;
    }

    private void loadCA() throws CertificateException {
        try {
            org.mozilla.jss.crypto.X509Certificate jssCert = this.cryptoManager
                .findCertByNickname(this.caKeyTokenPrefix + this.pKeyAlias);
            ByteArrayInputStream bis = new ByteArrayInputStream(
                jssCert.getEncoded());
            this.caCert = (X509Certificate) certFactory
                .generateCertificate(bis);

            this.pKey = this.cryptoManager.findPrivKeyByCert(jssCert);
        }
        catch (TokenException e) {
            log.error("Error Accessing JSS CryptoManager", e);
            throw new CertificateException(e);
        }
        catch (ObjectNotFoundException e) {
            log.error("Error Accessing JSS CryptoManager", e);
            throw new CertificateException(e);
        }

    }

    private Set<X509Certificate> loadUpstreamCACertificates(String path) {
        InputStream inStream = null;
        Set<X509Certificate> result = new HashSet<X509Certificate>();
        File dir = new File(path);
        if (!dir.exists()) {
            return result;
        }
        for (File file : dir.listFiles()) {
            try {
                inStream = new FileInputStream(file.getAbsolutePath());
                X509Certificate cert = (X509Certificate) this.certFactory
                    .generateCertificate(inStream);
                inStream.close();
                result.add(cert);
            }
            catch (Exception e) {
                throw new RuntimeException(e);
            }
            finally {
                try {
                    if (inStream != null) {
                        inStream.close();
                    }
                }
                catch (IOException e) {
                    // ignore. there's nothing we can do.
                }
            }
        }
        return result;
    }

}

class JSSPasswordCallback implements PasswordCallback {

    /*
     * (non-Javadoc)
     * @see
     * org.mozilla.jss.util.PasswordCallback#getPasswordAgain(org.mozilla.jss
     * .util.PasswordCallbackInfo)
     */
    @Override
    public Password getPasswordAgain(PasswordCallbackInfo arg0)
        throws GiveUpException {
        System.out.println("HELLO!");
        return new Password("password".toCharArray());
    }

    /*
     * (non-Javadoc)
     * @see
     * org.mozilla.jss.util.PasswordCallback#getPasswordFirstAttempt(org.mozilla
     * .jss.util.PasswordCallbackInfo)
     */
    @Override
    public Password getPasswordFirstAttempt(PasswordCallbackInfo arg0)
        throws GiveUpException {
        System.out.println("HELLO!");
        return new Password("password".toCharArray());
    }

}