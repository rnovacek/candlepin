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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import org.apache.commons.codec.binary.Base64;

import com.google.inject.Inject;

/**
 * PemEncoder: Utility class for PEM encoding a variety of objects.
 */
public class PEMEncoder {

    @Inject
    public PEMEncoder() {

    }

    private byte[] getPemEncoded(String type, byte[] data) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        Base64 b64 = new Base64(64);
        String header = "-----BEGIN " + type + "-----\r\n";
        String footer = "-----END " + type + "-----\r\n";
        byteArrayOutputStream.write(header.getBytes());
        byteArrayOutputStream.write(b64.encode(data));
        byteArrayOutputStream.write(footer.getBytes());
        byteArrayOutputStream.close();
        return byteArrayOutputStream.toByteArray();
    }

    /**
     * Take an X509Certificate object and return a byte[] of the certificate,
     * PEM encoded
     * @param cert
     * @return PEM-encoded bytes of the certificate
     * @throws IOException if there is i/o problem
     */
    public byte[] getPemEncoded(X509Certificate cert) throws IOException {
        try {
            return getPemEncoded("CERTIFICATE", cert.getEncoded());
        }
        catch (CertificateEncodingException e) {
            throw new IOException(e);
        }
    }

    public byte[] getPemEncoded(Key key) throws IOException {
        return getPemEncoded("RSA PRIVATE KEY", key.getEncoded());
    }

    public byte[] getPemEncoded(X509CRL crl) throws IOException {
        try {
            return getPemEncoded("X509 CRL", crl.getEncoded());
        }
        catch (CRLException e) {
            throw new IOException(e);
        }
    }


}
