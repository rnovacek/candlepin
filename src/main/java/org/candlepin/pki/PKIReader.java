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
package org.candlepin.pki;

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

/**
 * A generic mechanism for reading CA certificates from an underlying datastore.
 */
public abstract class PKIReader {
    /**
     * Supplies the CA's {@link X509Certificate}.
     *
     * @return a new Cert
     * @throws IOException if a file can't be read or is not found
     * @throws CertificateException  if there is an error from the underlying cert factory
     */
    public abstract X509Certificate getCACert() throws IOException, CertificateException;

    public abstract Set<X509Certificate> getUpstreamCACerts()
        throws IOException, CertificateException;

    /**
     * Supplies the CA's {@link PrivateKey}.
     *
     * @return a new PrivateKey
     * @throws IOException if a file can't be read or is not found
     * @throws GeneralSecurityException if something violated policy
     */
    public abstract PrivateKey getCAKey() throws IOException, GeneralSecurityException;

    protected X509Certificate loadCACertificate(String path) {
        InputStream inStream = null;
        try {
            inStream = new FileInputStream(path);
            X509Certificate cert = (X509Certificate) getCertFactory()
                .generateCertificate(inStream);
            inStream.close();
            return cert;
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

    protected Set<X509Certificate> loadUpstreamCACertificates(String path) {
        InputStream inStream = null;
        Set<X509Certificate> result = new HashSet<X509Certificate>();
        File dir = new File(path);
        if (!dir.exists()) {
            return result;
        }
        for (File file : dir.listFiles()) {
            try {
                inStream = new FileInputStream(file.getAbsolutePath());
                X509Certificate cert = (X509Certificate) getCertFactory()
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

    protected abstract CertificateFactory getCertFactory();
}
