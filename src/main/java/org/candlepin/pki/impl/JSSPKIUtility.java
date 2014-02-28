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

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.jce.PrincipalUtil;
import org.candlepin.config.Config;
import org.candlepin.config.ConfigProperties;
import org.candlepin.exceptions.IseException;
import org.candlepin.pki.PKIReader;
import org.candlepin.pki.PKIUtility;
import org.candlepin.pki.X509ByteExtensionWrapper;
import org.candlepin.pki.X509CRLEntryWrapper;
import org.candlepin.pki.X509ExtensionWrapper;
import org.candlepin.util.CrlFileUtil;
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
import java.io.CharConversionException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.Formatter;
import java.util.List;
import java.util.Set;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

/**
 * A JSS implementation of {@link PKIUtility} for Candlepin.
 *
 * This class implements methods to create X509 Certificates, X509 CRLs, encode
 * objects in PEM format (for saving to the db or sending to the client), and
 * decode raw ASN.1 DER values (as read from a Certificate/CRL).
 *
 * The implementation was created for FIPS compliance reasons to replace the previous
 * bouncycastle implementation, which is not FIPS certified.
 *
 * We do however continue to use bouncycastle for some ASN1 and DER encoding in this class,
 * but not for any actual crypto/hashing.
 *
 *
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

    private static final String SUBJECT_ALT_NAME_OID = "2.5.29.17";
    private static final String KEY_USAGE_OID = "2.5.29.15";
    private static final String AUTHORITY_KEY_IDENTIFIER_OID = "2.5.29.35";
    private static final String SUBJECT_KEY_IDENTIFIER_OID = "2.5.29.14";
    private static final String EXTENDED_KEY_USAGE_OID = "2.5.29.37";
    private static final String NETSCAPE_CERT_TYPE_OID = "2.16.840.1.113730.1.1";

    private static final String OPENSSL_INDEX_FILENAME = "certindex";
    private static final String OPENSSL_CRL_NUMBER_FILENAME = "crlnumber";
    private static final String OPENSSL_CONF_FILENAME = "openssl.conf";
    private static final String OPENSSL_CRL_FILENAME = "crl.pem";

    private static final String ASN1_DATE_FORMAT = "yyMMddHHmmss'Z'";

    private final File baseDir;
    private CrlFileUtil crlFileUtil;

    @Inject
    public JSSPKIUtility(PKIReader reader, Config config, CrlFileUtil crlFileUtil) {
        super(reader);
        this.crlFileUtil = crlFileUtil;

        // Make sure the base CRL work dir exists:
        baseDir = new File(config.getString(ConfigProperties.CRL_WORK_DIR));
        if (!baseDir.exists() && !baseDir.mkdirs()) {
            throw new IseException(
                "Unable to create base dir for CRL generation: " + baseDir);
        }
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

            // Add SSL extensions - required for proper X509. Value is sslClient | smime.
            BIT_STRING certType = new BIT_STRING(new byte[]{(byte) (128 | 32)}, 0);
            this.addExtension(cInfo, NETSCAPE_CERT_TYPE_OID, false, certType);

            // Set key usage - required for proper X509. Key usage is
            // digitalSignature | keyEncipherment | dataEncipherment.
            BIT_STRING keyUsage = new BIT_STRING(new byte[]{(byte) (128 | 32 | 16)}, 0);
            this.addExtension(cInfo, KEY_USAGE_OID, false, keyUsage);

            setAuthorityKeyIdentifier(cInfo, caCert);
            setSubjectKeyIdentifier(clientKeyPair, cInfo);

            // Add Extended Key Usage
            SEQUENCE seq = new SEQUENCE();
            seq.addElement(new OBJECT_IDENTIFIER("1.3.6.1.5.5.7.3.2"));
            this.addExtension(cInfo, EXTENDED_KEY_USAGE_OID, false, seq);

            // Add an alternate name if provided:
            if (alternateName != null) {
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
            Certificate cert = new Certificate(cInfo, reader.getCAKey(), sigAlg);
            ByteArrayInputStream bis = new ByteArrayInputStream(ASN1Util.encode(cert));
            return (X509Certificate) certFactory.generateCertificate(bis);
        }
        catch (InvalidBERException e) {
            throw new RuntimeException(e);
        }
        catch (NotInitializedException e) {
            throw new RuntimeException(e);
        }
        catch (TokenException e) {
            throw new RuntimeException(e);
        }
    }

    /*
     * Add the authority key identifier sequence to the certificate.
     *
     * AKI is a sequence of three elements, the SHA1 of the CA public key, the issuer,
     * and the CA cert serial.
     *
     * Uses bouncycastle for dealing with ASN1 and DER, but no actual crypto/hashing.
     */
    private void setAuthorityKeyIdentifier(CertificateInfo cInfo,
        X509Certificate caCert)
        throws CertificateException, IOException {

        byte [] subjectKeyIdentifier = getPublicKeyHash(caCert.getPublicKey());

        // Use bouncycastle objects to get our sequence. This code is based on what
        // happens behind the scenes in the bouncycastle AuthorityKeyIdentifierSequence
        // class.
        GeneralName genName = new GeneralName(PrincipalUtil.getIssuerX509Principal(caCert));
        GeneralNames issuer = new GeneralNames(genName);
        DERInteger certSerialNumber = new DERInteger(caCert.getSerialNumber());
        ASN1EncodableVector  v = new ASN1EncodableVector();
        v.add(new DERTaggedObject(false, 0, new DEROctetString(subjectKeyIdentifier)));
        v.add(new DERTaggedObject(false, 1, issuer));
        v.add(new DERTaggedObject(false, 2, certSerialNumber));
        DERSequence seq = new DERSequence(v);
        DERObject asn1 = seq.toASN1Object();

        Extension ext = new Extension(
            new OBJECT_IDENTIFIER(AUTHORITY_KEY_IDENTIFIER_OID),
            false,
            new OCTET_STRING(asn1.getDEREncoded()));
        cInfo.addExtension(ext);
    }

    /*
     * Adds the subject key identifier extension.
     *
     * This is a SHA1 of the subject's DER encoded public key.
     *
     * The process to get the DER encoded public key is somewhat involved, so to avoid
     * having to write something ourselves this method uses bouncycastle *only* for
     * ASN1 and DER work, then switches back to JSS to compute the actual SHA1 hash.
     * Thus we remain FIPS compliant in that we do not use bouncycastle for any
     * crypto/hashing.
     */
    private void setSubjectKeyIdentifier(KeyPair clientKeyPair,
        CertificateInfo cInfo) throws IOException, CertificateException {

        PublicKey pubKey = clientKeyPair.getPublic();

        // This code roughly follows what bouncycastle does behind the scenes in it's
        // SubjectKeyIdentifierStructure class.
        byte[] keyData = null;
        keyData = getPublicKeyHash(pubKey);

        OCTET_STRING subjectKeyString = new OCTET_STRING(keyData);
        this.addExtension(cInfo, SUBJECT_KEY_IDENTIFIER_OID, false, subjectKeyString);
    }

    private byte[] getPublicKeyHash(PublicKey pubKey) throws IOException {
        byte[] keyData;
        ASN1InputStream aIn = null;
        try {
            aIn = new ASN1InputStream(pubKey.getEncoded());
            ASN1Object obj = (ASN1Object) aIn.readObject();
            ASN1Sequence seq = ASN1Sequence.getInstance(obj);

            Enumeration e = seq.getObjects();
            org.bouncycastle.asn1.x509.AlgorithmIdentifier algId =
                org.bouncycastle.asn1.x509.AlgorithmIdentifier.getInstance(e.nextElement());
            DERBitString derKeyData = DERBitString.getInstance(e.nextElement());

            keyData = derKeyData.getBytes();

            // Calculate the SHA1 hash using JSS:
            keyData = sha1Digest(keyData);

        }
        finally {
            aIn.close();
        }
        return keyData;
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
            throw new RuntimeException(e);
        }

        Extension ext = new Extension(
            new OBJECT_IDENTIFIER(wrapper.getOid()),
            wrapper.isCritical(),
            new OCTET_STRING(ASN1Util.encode(extValue)));
        cInfo.addExtension(ext);
    }

    /**
     * Calculates the SHA1 hash for the given DER encoded public key using JSS.
     *
     * @param data DER encoded public key.
     * @return SHA1 hash
     */
    protected byte[] sha1Digest(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1", "Mozilla-JSS");
            return digest.digest(data);
        }
        catch (NoSuchAlgorithmException e) {
            log.error("NoSuchAlgorithmException:", e);
            throw new RuntimeException(e);
        }
        catch (NoSuchProviderException e) {
            log.error("NoSuchProviderException:", e);
            throw new RuntimeException(e);
        }
    }

    /*
     * JSS provides no mechanism to generate CRLs. Instead of writing our own solution,
     * for now we will shellout to openssl to generate.
     */
    @Override
    public X509CRL createX509CRL(List<X509CRLEntryWrapper> entries, BigInteger crlNumber) {
        try {
            // Make a temporary directory where we'll do our openssl work:
            File workDir = makeTempWorkDir();
            log.debug("Created temporary CRL dir: {}",
                workDir.getAbsolutePath());
            writeOpensslIndexFiles(workDir, entries);
            File configFile = writeOpensslConfig(workDir);
            writeOpensslCRLNumberFile(workDir, crlNumber);

            // Now we shell out to openssl to create our CRL:
            StringBuilder sb = new StringBuilder("openssl ca");
            sb.append(" -config ");
            sb.append(configFile.getAbsolutePath());
            sb.append(" -gencrl");
            sb.append(" -keyfile /etc/candlepin/certs/candlepin-ca.key");
            sb.append(" -cert /etc/candlepin/certs/candlepin-ca.crt");
            sb.append(" -out ");
            sb.append(workDir.getAbsolutePath());
            sb.append("/");
            sb.append(OPENSSL_CRL_FILENAME);
            executeCommand(sb.toString());

            // Now we read the CRL PEM and return the resulting object:
            File crlResult = new File(workDir, OPENSSL_CRL_FILENAME);
            X509CRL crl = crlFileUtil.readCRLFile(crlResult);

            try {
                log.debug("Cleaning up temporary CRL dir: {}", workDir.getAbsolutePath());
                FileUtils.deleteDirectory(workDir);
            }
            catch (IOException io) {
                // Everything likely succeeded except deleting the CRL dir, will log
                // and ignore this exception.
                log.error("Unable to delete temporary CRL dir: " +
                    workDir.getAbsolutePath(), io);
            }

            return crl;
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void executeCommand(String cmd) throws Exception {
        log.debug("Executing command: " + cmd);
        Process p = Runtime.getRuntime().exec(cmd);
        if (p.waitFor() != 0) {
            // Log stderr if there was a problem:
            StringWriter writer = new StringWriter();
            IOUtils.copy(p.getErrorStream(), writer);
            log.error("Error generating CRL with command: " + cmd);
            log.error(writer.toString());
            throw new RuntimeException("Error generating CRL");
        }
    }

    private File makeTempWorkDir() throws IOException {
        File tmp = File.createTempFile("CRL", Long.toString(System.nanoTime()),
            baseDir);

        if (!tmp.delete()) {
            throw new RuntimeException("Could not delete temp file: " +
                tmp.getAbsolutePath());
        }

        if (!tmp.mkdirs()) {
            throw new RuntimeException(
                "Could not create temp directory for CRL generation: " +
                    tmp.getAbsolutePath());
        }

        return (tmp);
    }

   /*
    * Openssl requires an index file containing information about the certificates to
    * revoke. Each line of this file looks like:
    *
    * E|R|V<tab>ExpiryDate<tab>[RevocationDate]<tab>Serial<tab>unknown<tab>SubjectDN
    *
    * Before we can generate we write out a temporary index file, which we use when we
    * shell out to openssl.
    */
    private File writeOpensslIndexFiles(File workDir, List<X509CRLEntryWrapper> entries)
        throws FileNotFoundException, UnsupportedEncodingException {
        File index = new File(workDir, OPENSSL_INDEX_FILENAME);
        log.debug("Writing OpenSSL index file: {}", index.getAbsolutePath());
        PrintWriter writer = new PrintWriter(index, "UTF-8");
        for (X509CRLEntryWrapper entry : entries) {
            Formatter f = new Formatter();

            // TODO: stop doing fake expiration dates
            Calendar cal = Calendar.getInstance();
            cal.setTime(entry.getRevocationDate());
            cal.add(Calendar.YEAR, 5);
            Date fakeExpiration = cal.getTime();

            String line = f.format("R\t%s\t%s\t%s\tunknown\t%s",
                getASN1Date(fakeExpiration),
                getASN1Date(entry.getRevocationDate()),
                padSerial(entry.getSerialNumber()),
                entry.getSubject()).toString();
            log.debug(line);
            writer.println(line);
            f.close();
        }
        writer.close();

        /*
         * We also need certindex.attr, openssl would generate this for us if we were using
         * it to manage certs. Instead we must write out the one attribute that is needed.
         */
        File indexAttr = new File(workDir, OPENSSL_INDEX_FILENAME + ".attr");
        log.debug("Writing OpenSSL index attr file: {}", indexAttr.getAbsolutePath());
        writer = new PrintWriter(indexAttr, "UTF-8");
        writer.println("unique_subject = yes");
        writer.close();

        // Return the index file we wrote:
        return index;
    }

    private File writeOpensslCRLNumberFile(File workDir, BigInteger crlNumber)
        throws FileNotFoundException, UnsupportedEncodingException {
        File indexAttr = new File(workDir, OPENSSL_CRL_NUMBER_FILENAME);
        log.debug("Writing OpenSSL crlnumber file: {}, crl number: {}",
            indexAttr.getAbsolutePath(), crlNumber);
        PrintWriter writer = new PrintWriter(indexAttr, "UTF-8");
        writer.println(padSerial(crlNumber));
        writer.close();
        return indexAttr;
    }

    /**
     * OpenSSL requires serial numbers in hex form, with an even number of digits.
     *
     * @param serial
     * @return Padded string representation of serial for use with openssl files.
     */
    private String padSerial(BigInteger serial) {
        String serialStr = serial.toString(16);
        if (serialStr.length() % 2 != 0) {
            serialStr = "0" + serialStr;
        }
        return serialStr;
    }

    private String getASN1Date(Date date) {
        SimpleDateFormat sdf = new SimpleDateFormat(ASN1_DATE_FORMAT);
        return sdf.format(date);
    }

    private File writeOpensslConfig(File workDir) throws
    FileNotFoundException, UnsupportedEncodingException {
        String fileContents =
            "[ ca ]\n" +
            "default_ca = CA_default\n" +
            "\n" +
            "[ CA_default ]\n" +
            "dir = " + workDir.getAbsolutePath() + "\n" +
            "certificate = $dir/ca.crt\n" +
            "database = $dir/certindex\n" +
            "private_key = $dir/ca.key\n" +
            "serial = $dir/certserial\n" +
            "default_md = sha1\n" +
            "crlnumber = $dir/crlnumber\n" +
            "crl_extensions = crl_ext\n" +
            "default_crl_days = 1\n" +
            "\n" +
            "[ crl_ext ]\n" +
            "authorityKeyIdentifier=keyid:always,issuer:always\n";
        File config = new File(workDir, OPENSSL_CONF_FILENAME);
        log.debug("Writing OpenSSL config file: {}", config.getAbsolutePath());
        PrintWriter writer = new PrintWriter(config, "UTF-8");
        writer.write(fileContents);
        writer.close();
        return config;
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
                    throw new RuntimeException(e);
                }
            }

            if (decoded != null) {
                try {
                    decoded.close();
                }
                catch (IOException e) {
                    log.warn("failed to close ASN1 stream", e);
                    throw new RuntimeException(e);
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
            throw new RuntimeException(e);
        }
        catch (CharConversionException e) {
            log.error("Found invalid Distinuguished Name " + name, e);
            throw new RuntimeException(e);
        }

        return name;
    }
}
