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

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import org.apache.commons.io.FileUtils;
import org.candlepin.model.RulesCurator;

import com.google.inject.Inject;

/**
 * RulesExporter
 */
public class RulesExporter {
    private static final String LEGACY_RULES_FILE = "/rules/default-rules.js";

    private RulesCurator rulesCurator;

    @Inject
    public RulesExporter(RulesCurator rulesCurator) {
        this.rulesCurator = rulesCurator;
    }

    void export(File baseDir) throws IOException {
        exportNewRules(baseDir);
        exportLegacyRules(baseDir);
    }

    private void exportNewRules(File baseDir) throws IOException {
        // Because old candlepin servers assume to import a file in rules dir, we had to
        // move to a new directory for versioned rules file:
        File newRulesDir = new File(baseDir.getCanonicalPath(), "rules2");
        newRulesDir.mkdir();
        File newRulesFile = new File(newRulesDir.getCanonicalPath(), "rules.js");
        FileWriter writer = new FileWriter(newRulesFile);
        writer.write(rulesCurator.getRules().getRules());
        writer.close();
    }

    private void exportLegacyRules(File baseDir) throws IOException {
        File oldRulesDir = new File(baseDir.getCanonicalPath(), "rules");
        oldRulesDir.mkdir();
        File oldRulesFile = new File(oldRulesDir.getCanonicalPath(), "default-rules.js");

        // 8
        FileUtils.copyFile(new File(
            this.getClass().getResource(LEGACY_RULES_FILE).getPath()),
            oldRulesFile);
    }
}
