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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
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

import com.google.inject.Inject;

/**
 * DefaultPKIReader. This reads a java keystore in PKCS12 format.
 * The private key and CA certificate are extracted from the
 * keystore and used by the utility to generate certificates
 */
public class DefaultPKIReader implements PKIReader {

    private static Logger log = Logger.getLogger(
        DefaultPKIReader.class);

    private CertificateFactory certFactory;
    private String caKeystore;
    private String upstreamCaCertPath;
    private String caKeyPassword;
    private String pKeyAlias;
    private KeyStore keystore;
    private PrivateKey pKey;
    private X509Certificate caCert;
    private Set<X509Certificate> upstreamX509Certificates;

    @Inject
    public DefaultPKIReader(Config config) throws CertificateException {
        certFactory = CertificateFactory.getInstance("X.509");
        this.upstreamCaCertPath = config.getString(ConfigProperties.CA_CERT_UPSTREAM);
        log.debug("Using caCertPath " + this.upstreamCaCertPath);
        this.caKeystore = config.getString(ConfigProperties.CA_KEYSTORE);
        log.debug("Using caKeystore " + this.caKeystore);
        this.pKeyAlias = config.getString(ConfigProperties.CA_KEY_ALIAS);
        log.debug("Using key alias " + this.pKeyAlias);
        Util.assertNotNull(this.pKeyAlias,
            "pKeyAlias cannot be null. Unable to load CA Certificate");
        this.caKeyPassword = config.getString(ConfigProperties.CA_KEY_PASSWORD);
        Util.assertNotNull(this.caKeystore,
            "caKeystore cannot be null. Unable to load CA Certificate");
        this.upstreamX509Certificates =
            this.loadUpstreamCACertificates(this.upstreamCaCertPath);
        this.loadCA(this.caKeystore);
    }


    /* (non-Javadoc)
     * @see org.candlepin.pki.PKIReader#getCACert()
     */
    @Override
    public X509Certificate getCACert() throws IOException, CertificateException {
        return this.caCert;
    }

    /* (non-Javadoc)
     * @see org.candlepin.pki.PKIReader#getUpstreamCACerts()
     */
    @Override
    public Set<X509Certificate> getUpstreamCACerts() throws IOException,
        CertificateException {
        return this.upstreamX509Certificates;
    }

    /* (non-Javadoc)
     * @see org.candlepin.pki.PKIReader#getCaKey()
     */
    @Override
    public PrivateKey getCaKey() throws IOException, GeneralSecurityException {
        return this.pKey;
    }

    private void loadCA(String path) throws CertificateException {
        try {
            this.keystore = KeyStore.getInstance("PKCS12");
            this.keystore.load(new FileInputStream(this.caKeystore),
                this.caKeyPassword.toCharArray());
            this.pKey = (PrivateKey) this.keystore.getKey(this.pKeyAlias,
                this.caKeyPassword.toCharArray());
            this.caCert = (X509Certificate) this.keystore.getCertificate("tomcat");

        }
        catch (KeyStoreException e) {
            log.error(e.getMessage());
            throw new CertificateException(e);
        }
        catch (FileNotFoundException e) {
            log.error(e.getMessage());
            throw new CertificateException(e);
        }
        catch (NoSuchAlgorithmException e) {
            log.error(e.getMessage());
            throw new CertificateException(e);
        }
        catch (IOException e) {
            log.error(e.getMessage());
            throw new CertificateException(e);
        }
        catch (UnrecoverableKeyException e) {
            log.error(e.getMessage());
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
