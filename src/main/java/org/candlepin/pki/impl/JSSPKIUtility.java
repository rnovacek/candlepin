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

import com.google.inject.Inject;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.candlepin.pki.PKIReader;
import org.candlepin.pki.PKIUtility;
import org.candlepin.pki.X509ByteExtensionWrapper;
import org.candlepin.pki.X509CRLEntryWrapper;
import org.candlepin.pki.X509ExtensionWrapper;
import org.candlepin.util.Util;
import org.mozilla.jss.CryptoManager.NotInitializedException;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.BIT_STRING;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.Tag;
import org.mozilla.jss.asn1.UTF8String;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.pkix.cert.Certificate;
import org.mozilla.jss.pkix.cert.CertificateInfo;
import org.mozilla.jss.pkix.cert.Extension;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.pkix.primitive.Name;
import org.mozilla.jss.pkix.primitive.SubjectPublicKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.CharConversionException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Set;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

/**
 * The default {@link PKIUtility} for Candlepin.
 * This class implements methods to create X509 Certificates, X509 CRLs, encode
 * objects in PEM format (for saving to the db or sending to the client), and
 * decode raw ASN.1 DER values (as read from a Certificate/CRL).
 *
 * All code that imports bouncycastle should live either in this module,
 * or in {@link BouncyCastlePKIReader}
 *
 * (March 24, 2011) Notes on implementing a PKIUtility with NSS/JSS:
 *
 * JSS provides classes and functions to generate X509Certificates (see CertificateInfo,
 * for example).
 *
 * PEM encoding requires us to determine the object type (which we know), add the correct
 * header and footer to the output, base64 encode the DER for the object, and line wrap
 * the base64 encoding.
 *
 * decodeDERValue should be simple, as JSS provides code to parse ASN.1, but I wasn't
 * able to get it to work.
 *
 * The big one is CRL generation. JSS has no code to generate CRLs in any format. We'll
 * have to use the raw ASN.1 libraries to build up our own properly formatted CRL DER
 * representation, then PEM encode it.
 *
 * See also {@link BouncyCastlePKIReader} for more notes on using NSS/JSS, and a note
 * about not using bouncycastle as the JSSE provider.
 */
@SuppressWarnings("deprecation")
public class JSSPKIUtility extends PKIUtility {
    private static Logger log = LoggerFactory.getLogger(JSSPKIUtility.class);

    protected SubjectKeyIdentifierWriter subjectKeyWriter;
    public static final String SUBJECT_ALT_NAME_OID = "2.5.29.17";
    public static final String KEY_USAGE_OID = "2.5.29.15";
    public static final String AUTHORITY_KEY_IDENTIFIER_OID = "2.5.29.35";
    public static final String SUBJECT_KEY_IDENTIFIER_OID = "2.5.29.14";
    public static final String EXTENDED_KEY_USAGE_OID = "2.5.29.37";
    public static final String NETSCAPE_CERT_TYPE_OID = "2.16.840.1.113730.1.1";

    @Inject
    public JSSPKIUtility(PKIReader reader,
        SubjectKeyIdentifierWriter subjectKeyWriter) {

        super(reader);
        this.subjectKeyWriter = subjectKeyWriter;
    }

    @Override
    public X509Certificate createX509Certificate(String dn,
        Set<X509ExtensionWrapper> extensions, Set<X509ByteExtensionWrapper> byteExtensions,
        Date startDate, Date endDate,
        KeyPair clientKeyPair, BigInteger serialNumber, String alternateName)
        throws GeneralSecurityException, IOException {

        try {
            X509Certificate caCert = reader.getCACert();
            SignatureAlgorithm sigAlg = null;
            if (SIGNATURE_ALGO == "SHA1WITHRSA") {
                sigAlg = SignatureAlgorithm.RSASignatureWithSHA1Digest;
            }
            Util.assertNotNull(sigAlg, "Signature Algorithm has changed");

            SubjectPublicKeyInfo subjectInfo = new SubjectPublicKeyInfo(
                clientKeyPair.getPublic());

            Name issuer = this.parseDN(caCert.getIssuerX500Principal().getName());

            CertificateInfo cInfo = new CertificateInfo(CertificateInfo.v3,
                new INTEGER(serialNumber),
                new AlgorithmIdentifier(sigAlg.toOID()),
                issuer,
                startDate,
                endDate,
                this.parseDN(dn),
                subjectInfo);


            // set key usage - required for proper x509 function
            // Key Usage is digitalSignature | keyEncipherment | dataEncipherment
            BIT_STRING keyUsage = new BIT_STRING(new byte[]{(byte) (128 | 32 | 16)}, 0);
            this.addExtension(cInfo, KEY_USAGE_OID, false, keyUsage);

            // add SSL extensions - required for proper x509 function
            // Value is sslClient | smime
            BIT_STRING certType = new BIT_STRING(new byte[]{(byte) (128 | 32)}, 0);
            this.addExtension(cInfo, NETSCAPE_CERT_TYPE_OID, false, certType);

            // The subject key identifier is a sha1 hash of the public key of the subject
            byte[] keyData = clientKeyPair.getPublic().getEncoded();
            keyData = this.sha1Digest(keyData);
            OCTET_STRING subjectKeyString = new OCTET_STRING(keyData);

            this.addExtension(cInfo, SUBJECT_KEY_IDENTIFIER_OID, false, subjectKeyString);

            // The authors key identifier is a sequence, with the first being the
            // sha1 of the ca key, and then the issuer, then the serial number
            keyData = caCert.getPublicKey().getEncoded();
            keyData = this.sha1Digest(keyData);
            subjectKeyString = new OCTET_STRING(keyData);


            // TODO: not coming out the same as the old bounceycastle code
            // This is an optional extension and generally used when an issuer has multiple
            // signing keys. Do we need to even bother setting this?
            SEQUENCE authKeySeq = new SEQUENCE();
            authKeySeq.addElement(new Tag(0), subjectKeyString);
            authKeySeq.addElement(new Tag(1), issuer);
            authKeySeq.addElement(new Tag(2), new INTEGER(caCert.getSerialNumber()));

            this.addExtension(cInfo, AUTHORITY_KEY_IDENTIFIER_OID, false, authKeySeq);

/*
            certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
                new AuthorityKeyIdentifierStructure(caCert));
            certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false,
                  subjectKeyWriter.getSubjectKeyIdentifier(clientKeyPair, extensions));
*/

            // Add Extended Key Usage
            SEQUENCE seq = new SEQUENCE();
            seq.addElement(new OBJECT_IDENTIFIER("1.3.6.1.5.5.7.3.2"));
            this.addExtension(cInfo, EXTENDED_KEY_USAGE_OID, false, seq);

            // Add an alternate name if provided
            if (alternateName != null) {
                // Compared to bouncecastle, missing DirName:/
                this.addExtension(cInfo, SUBJECT_ALT_NAME_OID, false, "CN=" +
                    alternateName);
            }


            if (extensions != null) {
                for (X509ExtensionWrapper wrapper : extensions) {
                    this.addExtension(cInfo, wrapper);
                }
            }

            if (byteExtensions != null) {
                for (X509ByteExtensionWrapper wrapper : byteExtensions) {
                    this.addExtension(cInfo, wrapper);
                }
            }

            // Generate the certificate
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            Certificate cert = new Certificate(cInfo, reader.getCaKey(), sigAlg);
            ByteArrayInputStream bis = new ByteArrayInputStream(ASN1Util.encode(cert));
            return (X509Certificate) certFactory.generateCertificate(bis);
        }
        catch (InvalidBERException e) {
            throw new GeneralSecurityException(e);
        }
        catch (NotInitializedException e) {
            throw new GeneralSecurityException(e);
        }
        catch (TokenException e) {
            throw new GeneralSecurityException(e);
        }
    }

    protected void addExtension(CertificateInfo cInfo, String oid,
        boolean isCritical, String value)
        throws  CertificateException {
        value = value == null ? "" :  value;
        Extension ext = new Extension(
            new OBJECT_IDENTIFIER(oid),
            isCritical,
            new OCTET_STRING(value.getBytes()));
        cInfo.addExtension(ext);
    }

    protected void addExtension(CertificateInfo cInfo, String oid,
        boolean isCritical, ASN1Value value)
        throws  CertificateException {
        Extension ext = new Extension(
            new OBJECT_IDENTIFIER(oid),
            isCritical,
            new OCTET_STRING(ASN1Util.encode(value)));
        cInfo.addExtension(ext);
    }

    protected void addExtension(CertificateInfo cInfo, X509ByteExtensionWrapper wrapper)
        throws  CertificateException {
        byte[] value = wrapper.getValue() == null ? new byte[0] :
            wrapper.getValue();

        OCTET_STRING extValue = new OCTET_STRING(value);


        Extension ext = new Extension(
            new OBJECT_IDENTIFIER(wrapper.getOid()),
            wrapper.isCritical(),
            new OCTET_STRING(ASN1Util.encode(extValue)));
        cInfo.addExtension(ext);
    }

    protected void addExtension(CertificateInfo cInfo, X509ExtensionWrapper wrapper)
        throws  CertificateException {
        String value = wrapper.getValue() == null ? "" :  wrapper.getValue();

        UTF8String extValue = null;
        try {
            extValue = new UTF8String(value);
        }
        catch (CharConversionException e) {
            // TODO: look at all error handling in here
            log.error("CharConversionException", e);
        }

        Extension ext = new Extension(
            new OBJECT_IDENTIFIER(wrapper.getOid()),
            wrapper.isCritical(),
            new OCTET_STRING(ASN1Util.encode(extValue)));
        cInfo.addExtension(ext);
    }

    protected byte[] sha1Digest(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1", "Mozilla-JSS");
            return digest.digest(data);
        }
        catch (NoSuchAlgorithmException e) {
            log.error("NoSuchAlgorithmException:", e);
        }
        catch (NoSuchProviderException e) {
            log.error("NoSuchProviderException:", e);
        }
        return new byte[0];
    }

    @Override
    public X509CRL createX509CRL(List<X509CRLEntryWrapper> entries, BigInteger crlNumber) {

        try {
            X509Certificate caCert = reader.getCACert();
            X509V2CRLGenerator generator = new X509V2CRLGenerator();
            generator.setIssuerDN(caCert.getIssuerX500Principal());
            generator.setThisUpdate(new Date());
            generator.setNextUpdate(Util.tomorrow());
            generator.setSignatureAlgorithm(SIGNATURE_ALGO);
            //add all the crl entries.
            for (X509CRLEntryWrapper entry : entries) {
                generator.addCRLEntry(entry.getSerialNumber(), entry.getRevocationDate(),
                    CRLReason.privilegeWithdrawn);
            }
            log.info("Completed adding CRL numbers to the certificate.");
            generator.addExtension(X509Extensions.AuthorityKeyIdentifier,
                false, new AuthorityKeyIdentifierStructure(caCert));
            generator.addExtension(X509Extensions.CRLNumber, false,
                new CRLNumber(crlNumber));
            return generator.generate(reader.getCaKey());
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
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
        log.error(new String(byteArrayOutputStream.toByteArray()));
        return byteArrayOutputStream.toByteArray();
    }

    @Override
    public byte[] getPemEncoded(X509Certificate cert) throws IOException {
        try {
            return getPemEncoded("CERTIFICATE", cert.getEncoded());
        }
        catch (CertificateEncodingException e) {
            throw new IOException(e);
        }
    }

    @Override
    public byte[] getPemEncoded(Key key) throws IOException {
        return getPemEncoded("RSA PRIVATE KEY", key.getEncoded());
    }

    @Override
    public byte[] getPemEncoded(X509CRL crl) throws IOException {
        try {
            return getPemEncoded("THINGY", crl.getEncoded());
        }
        catch (CRLException e) {
            throw new IOException(e);
        }
    }

    @Override
    public String decodeDERValue(byte[] value) {
        ASN1InputStream vis = null;
        ASN1InputStream decoded = null;
        try {
            vis = new ASN1InputStream(value);
            decoded = new ASN1InputStream(
                ((DEROctetString) vis.readObject()).getOctets());

            return decoded.readObject().toString();
        }
        catch (IOException e) {
            throw new RuntimeException(e);
        }
        finally {
            if (vis != null) {
                try {
                    vis.close();
                }
                catch (IOException e) {
                    log.warn("failed to close ASN1 stream", e);
                }
            }

            if (decoded != null) {
                try {
                    decoded.close();
                }
                catch (IOException e) {
                    log.warn("failed to close ASN1 stream", e);
                }
            }
        }
    }

    public Name parseDN(String nameString) {
        Name name = new Name();
        try {
            LdapName ldapName = new LdapName(nameString);
            for (Rdn rdn : ldapName.getRdns()) {
                String type = rdn.getType().toUpperCase();
                log.error(type);
                if (type.equals("CN")) {
                    name.addCommonName((String) rdn.getValue());
                }
                else if (type.equals("OU")) {
                    name.addOrganizationalUnitName((String) rdn.getValue());
                }
                else if (type.equals("O")) {
                    name.addOrganizationName((String) rdn.getValue());
                }
                else if (type.equals("C")) {
                    name.addCountryName((String) rdn.getValue());
                }
                else if (type.equals("L")) {
                    name.addLocalityName((String) rdn.getValue());
                }
                else if (type.equals("S")) {
                    name.addStateOrProvinceName((String) rdn.getValue());
                }
            }
        }
        catch (InvalidNameException e) {
            log.error("Found invalid Distinuguished Name " + name, e);
        }
        catch (CharConversionException e) {
            // TODO Auto-generated catch block
            log.error("Found invalid Distinuguished Name " + name, e);
        }

        return name;

    }
}
