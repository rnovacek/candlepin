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
package org.candlepin.manifest;

import com.google.inject.Inject;

import org.apache.log4j.Logger;
import org.candlepin.config.Config;
import org.candlepin.config.ConfigProperties;
import org.candlepin.model.Consumer;
import org.candlepin.pki.PKIUtility;
import org.codehaus.jackson.map.ObjectMapper;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Exporter
 */
public class ManifestExporter {
    private static Logger log = Logger.getLogger(ManifestExporter.class);

    private ObjectMapper mapper;

    private MetaExporter meta;
    private ConsumerExporter consumerExporter;
    private ProductExporter productExporter;
    private ConsumerTypeExporter consumerType;
    private RulesExporter rules;
    private EntitlementCertExporter entCert;
    private EntitlementExporter entExporter;
    private DistributorVersionExporter distVerExporter;

    private PKIUtility pki;
    private Config config;
    private IdentityCertificateExporter idcertExporter;


    @Inject
    public ManifestExporter(MetaExporter meta,
        ConsumerExporter consumerExporter, ConsumerTypeExporter consumerType,
        RulesExporter rules, EntitlementCertExporter entCert,
        ProductExporter productExporter,
        EntitlementExporter entExporter,
        PKIUtility pki, Config config,
        IdentityCertificateExporter idcertExporter,
        DistributorVersionExporter distVerExporter) {

        this.meta = meta;
        this.consumerExporter = consumerExporter;
        this.consumerType = consumerType;
        this.rules = rules;
        this.entCert = entCert;
        this.productExporter = productExporter;
        this.entExporter = entExporter;
        this.pki = pki;
        this.config = config;
        this.distVerExporter = distVerExporter;
        this.idcertExporter = idcertExporter;

        mapper = SyncUtils.getObjectMapper(this.config);
    }

    public File getFullExport(Consumer consumer) throws ExportCreationException {
        // TODO: need to delete tmpDir (which contains the archive,
        // which we need to return...)
        try {
            File tmpDir = new SyncUtils(config).makeTempDir("export");
            File baseDir = new File(tmpDir.getAbsolutePath(), "export");
            baseDir.mkdir();

            exportMeta(baseDir);
            exportConsumer(baseDir, consumer);
            exportIdentityCertificate(baseDir, consumer);
            exportEntitlements(baseDir, consumer);
            exportEntitlementsCerts(baseDir, consumer, null, true);
            exportProducts(baseDir, consumer);
            exportConsumerTypes(baseDir);
            exportRules(baseDir);
            exportDistributorVersions(baseDir);
            return makeArchive(consumer, tmpDir, baseDir);
        }
        catch (IOException e) {
            log.error("Error generating entitlement export", e);
            throw new ExportCreationException("Unable to create export archive", e);
        }
    }

    public File getEntitlementExport(Consumer consumer,
                        Set<Long> serials) throws ExportCreationException {
        // TODO: need to delete tmpDir (which contains the archive,
        // which we need to return...)
        try {
            File tmpDir = new SyncUtils(config).makeTempDir("export");
            File baseDir = new File(tmpDir.getAbsolutePath(), "export");
            baseDir.mkdir();

            exportMeta(baseDir);
            exportEntitlementsCerts(baseDir, consumer, serials, false);
            return makeArchive(consumer, tmpDir, baseDir);
        }
        catch (IOException e) {
            log.error("Error generating entitlement export", e);
            throw new ExportCreationException("Unable to create export archive", e);
        }
    }

    /**
     * Create a tar.gz archive of the exported directory.
     *
     * @param exportDir Directory where Candlepin data was exported.
     * @return File reference to the new archive zip.
     */
    private File makeArchive(Consumer consumer, File tempDir, File exportDir)
        throws IOException {
        String exportFileName = exportDir.getName() + ".zip";
        log.info("Creating archive of " + exportDir.getAbsolutePath() + " in: " +
            exportFileName);

        File archive = createZipArchiveWithDir(
            tempDir, exportDir, "consumer_export.zip",
            "Candlepin export for " + consumer.getUuid());

        InputStream archiveInputStream = null;
        try {
            archiveInputStream = new FileInputStream(archive);
            File signedArchive = createSignedZipArchive(
                tempDir, archive, exportFileName,
                pki.getSHA256WithRSAHash(archiveInputStream),
                "signed Candlepin export for " + consumer.getUuid());

            log.debug("Returning file: " + archive.getAbsolutePath());
            return signedArchive;
        }
        finally {
            if (archiveInputStream != null) {
                try {
                    archiveInputStream.close();
                }
                catch (Exception e) {
                    // nothing to do
                }
            }
        }
    }

    private File createZipArchiveWithDir(File tempDir, File exportDir,
        String exportFileName, String comment)
        throws FileNotFoundException, IOException {

        File archive = new File(tempDir, exportFileName);
        ZipOutputStream out = null;
        try {
            out = new ZipOutputStream(new FileOutputStream(archive));
            out.setComment(comment);
            addFilesToArchive(out, exportDir.getParent().length() + 1, exportDir);
        }
        finally {
            if (out != null) {
                out.close();
            }
        }
        return archive;
    }

    private File createSignedZipArchive(File tempDir, File toAdd,
        String exportFileName, byte[] signature, String comment)
        throws FileNotFoundException, IOException {

        File archive = new File(tempDir, exportFileName);
        ZipOutputStream out = null;
        try {
            out = new ZipOutputStream(new FileOutputStream(archive));
            out.setComment(comment);
            addFileToArchive(out, toAdd.getParent().length() + 1, toAdd);
            addSignatureToArchive(out, signature);
        }
        finally {
            if (out != null) {
                out.close();
            }
        }
        return archive;
    }



    /**
     * @param out
     * @param exportDir
     * @throws IOException
     */
    private void addFilesToArchive(ZipOutputStream out, int charsToDropFromName,
        File directory) throws IOException {
        for (File file : directory.listFiles()) {
            if (file.isDirectory()) {
                addFilesToArchive(out, charsToDropFromName, file);
            }
            else {
                addFileToArchive(out, charsToDropFromName, file);
            }
        }
    }

    private void addFileToArchive(ZipOutputStream out, int charsToDropFromName,
        File file) throws IOException, FileNotFoundException {
        log.debug("Adding file to archive: " +
            file.getAbsolutePath().substring(charsToDropFromName));
        out.putNextEntry(new ZipEntry(
            file.getAbsolutePath().substring(charsToDropFromName)));
        FileInputStream in = new FileInputStream(file);

        byte [] buf = new byte[1024];
        int len;
        while ((len = in.read(buf)) > 0) {
            out.write(buf, 0, len);
        }
        out.closeEntry();
        in.close();
    }

    private void addSignatureToArchive(ZipOutputStream out, byte[] signature)
        throws IOException, FileNotFoundException {

        log.debug("Adding signature to archive.");
        out.putNextEntry(new ZipEntry("signature"));
        out.write(signature, 0, signature.length);
        out.closeEntry();
    }

    private void exportMeta(File baseDir) throws IOException {
        meta.export(mapper, baseDir, getPrefixWebUrl());
    }

    private String getPrefixWebUrl() {
        String prefixWebUrl = config.getString(ConfigProperties.PREFIX_WEBURL);
        if (prefixWebUrl != null && prefixWebUrl.trim().equals("")) {
            prefixWebUrl = null;
        }
        return prefixWebUrl;
    }

    private String getPrefixApiUrl() {
        String prefixApiUrl = config.getString(ConfigProperties.PREFIX_APIURL);
        if (prefixApiUrl != null && prefixApiUrl.trim().equals("")) {
            prefixApiUrl = null;
        }
        return prefixApiUrl;
    }

    private void exportConsumer(File baseDir, Consumer consumer) throws IOException {
        this.consumerExporter.export(mapper, baseDir, consumer, getPrefixWebUrl(),
            getPrefixApiUrl());
    }

    private void exportEntitlementsCerts(File baseDir,
                                         Consumer consumer,
                                         Set<Long> serials,
                                         boolean manifest)
        throws IOException {

        entCert.export(baseDir, consumer, serials, manifest);
    }

    private void exportIdentityCertificate(File baseDir, Consumer consumer)
        throws IOException {

        idcertExporter.export(mapper, baseDir, consumer);
    }

    private void exportEntitlements(File baseDir, Consumer consumer)
        throws IOException, ExportCreationException {
        entExporter.export(mapper, baseDir, consumer);
    }

    private void exportProducts(File baseDir, Consumer consumer) throws IOException {
        productExporter.export(mapper, baseDir, consumer);
    }

    private void exportConsumerTypes(File baseDir) throws IOException {
        consumerType.export(mapper, baseDir);
    }

    private void exportRules(File baseDir) throws IOException {
        rules.export(baseDir);
    }

    private void exportDistributorVersions(File baseDir) throws IOException {
        distVerExporter.export(mapper, baseDir);
    }
}
