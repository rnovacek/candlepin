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

import com.google.inject.Inject;

import org.apache.commons.io.IOUtils;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.ANY;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.BMPString;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.pkcs12.AuthenticatedSafes;
import org.mozilla.jss.pkcs12.PFX;
import org.mozilla.jss.pkcs12.PasswordConverter;
import org.mozilla.jss.pkcs12.SafeBag;
import org.mozilla.jss.pkix.primitive.Attribute;
import org.mozilla.jss.pkix.primitive.EncryptedPrivateKeyInfo;
import org.mozilla.jss.pkix.primitive.PrivateKeyInfo;
import org.mozilla.jss.util.Password;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Set;

/**
 * This class will not work if CryptoManager.initialize has not been called!
 */
public class JSSPKIReader extends PKIReader {
    private static Logger log = LoggerFactory.getLogger(JSSPKIReader.class);

    private CertificateFactory certFactory;
    private KeyPair keyPair;
    private X509Certificate caCert;
    private Set<X509Certificate> upstreamX509Certificates;

    @Inject
    public JSSPKIReader(Config config, CryptoManager manager) throws GeneralSecurityException {
        String upstreamCaCertPath = config.getString(ConfigProperties.CA_CERT_UPSTREAM);
        String caPath = config.getString(ConfigProperties.CA_CERT);
        String passwordPath = config.getString(ConfigProperties.CA_KEYSTORE_PASSWORD_FILE);
        String keystorePath = config.getString(ConfigProperties.CA_KEYSTORE);
        String nickname = config.getString(ConfigProperties.CA_KEYSTORE_NICKNAME);

        try {
            certFactory = CertificateFactory.getInstance("X.509");

            Reader passwordReader = new FileReader(
                new File(passwordPath));
            InputStream keystoreStream = new BufferedInputStream(
                new FileInputStream(new File(keystorePath)), 2048);

            keyPair = getPrivateKey(passwordReader, keystoreStream, nickname);
            passwordReader.close();
        }
        catch (FileNotFoundException e) {
            throw new GeneralSecurityException(e);
        }
        catch (InvalidKeyException e) {
            throw new GeneralSecurityException(e);
        }
        catch (IOException e) {
            throw new GeneralSecurityException(e);
        }

        upstreamX509Certificates = loadUpstreamCACertificates(upstreamCaCertPath);
        caCert = loadCACertificate(caPath);
    }

    private KeyPair getPrivateKey(Reader passwordReader, InputStream keystoreStream,
        String nickname) throws GeneralSecurityException {
        try {
            PFX.Template template = new PFX.Template();
            PFX keystore = (PFX) template.decode(keystoreStream);

            AuthenticatedSafes authSafes = keystore.getAuthSafes();
            SEQUENCE safesSequence = authSafes.getSequence();

            char[] passwordArray = IOUtils.toString(passwordReader).trim().toCharArray();
            Password password = new Password(passwordArray);
            for (int i = 0; i < safesSequence.size(); i++) {
                SEQUENCE contents = authSafes.getSafeContentsAt(password, i);
                for (int j = 0; j < contents.size(); j++) {
                    SafeBag safeBag = (SafeBag) contents.elementAt(j);

                    if (entryMatchesName(safeBag, nickname)) {

                        ASN1Value asnVal = safeBag.getInterpretedBagContent();

                        if (asnVal instanceof PrivateKeyInfo) {
                            return extractPrivateKeyFromCertBag((PrivateKeyInfo) asnVal);
                        }
                        else if (asnVal instanceof EncryptedPrivateKeyInfo) {
                            return extractEncryptedPrivateKeyFromCertBag(
                                (EncryptedPrivateKeyInfo) asnVal, password);
                        }
                    }
                }
            }
        }
        catch (GeneralSecurityException e) {
            throw e;
        }
        catch (Exception e) {
            // getSafeContentsAt() has a billion checked exceptions so catch them all
            throw new InvalidKeyException(e);
        }
        throw new GeneralSecurityException("Could not find matching key in PKCS12 keystore!");
    }

    private boolean entryMatchesName(SafeBag safeBag, String nickname) throws InvalidBERException {
        SET attrs = safeBag.getBagAttributes();
        if (attrs == null) {
            return false;
        }

        for (int i = 0; i < attrs.size(); i++) {
            Attribute a = (Attribute) attrs.elementAt(i);
            if (SafeBag.FRIENDLY_NAME.equals(a.getType())) {
                BMPString bs = (BMPString) ((ANY) a.getValues().elementAt(0))
                    .decodeWith(BMPString.getTemplate());
                return nickname.equals(bs.toString());
            }
        }
        return false;
    }

    private KeyPair extractEncryptedPrivateKeyFromCertBag(EncryptedPrivateKeyInfo epki,
        Password password) throws GeneralSecurityException {
        try {
            PrivateKeyInfo pki = epki.decrypt(password, new PasswordConverter());
            return extractPrivateKeyFromCertBag(pki);
        }
        catch (GeneralSecurityException e) {
            throw e;
        }
        catch (Exception e) {
            throw new GeneralSecurityException(e);
        }
    }

    private KeyPair extractPrivateKeyFromCertBag(PrivateKeyInfo pki) throws GeneralSecurityException {
        for (Provider p : Arrays.asList(Security.getProviders())) {
            log.info("Provider is {}", p.getName());
        }

        try {
            KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
            log.info(pki.getFormat());
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            pki.encode(baos);

            KeySpec pkcs8Spec = new PKCS8EncodedKeySpec(baos.toByteArray());
            RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey)
                rsaKeyFactory.generatePrivate(pkcs8Spec);
            RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(
                privateKey.getModulus(), privateKey.getPublicExponent());

            return new KeyPair(
                rsaKeyFactory.generatePublic(pubSpec),
                privateKey);
        }
        catch (IOException e) {
            throw new GeneralSecurityException(e);
        }
        catch (NoSuchAlgorithmException e) {
            throw new GeneralSecurityException(e);
        }
        catch (InvalidKeySpecException e) {
            throw new GeneralSecurityException(e);
        }
    }

    @Override
    protected CertificateFactory getCertFactory() {
        return certFactory;
    }

    @Override
    public X509Certificate getCACert() {
        return caCert;
    }

    @Override
    public Set<X509Certificate> getUpstreamCACerts() {
        return upstreamX509Certificates;
    }

    @Override
    public PrivateKey getCAKey() {
        return keyPair.getPrivate();
    }
}

