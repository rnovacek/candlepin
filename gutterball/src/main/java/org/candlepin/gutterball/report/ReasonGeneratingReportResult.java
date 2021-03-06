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
package org.candlepin.gutterball.report;

import org.candlepin.gutterball.model.snapshot.Compliance;
import org.candlepin.gutterball.model.snapshot.ComplianceReason;
import org.candlepin.gutterball.model.snapshot.Consumer;

import java.util.Iterator;



/**
 * The ReasonGeneratingReportResult class represents an IterableReportResult that generates
 * compliance reasons for each outbound compliance.
 */
public class ReasonGeneratingReportResult extends IterableReportResult<Compliance> {

    private StatusReasonMessageGenerator messageGenerator;

    public ReasonGeneratingReportResult(Iterator<Compliance> results,
        StatusReasonMessageGenerator messageGenerator) {
        super(results);

        if (messageGenerator == null) {
            throw new IllegalArgumentException("messageGenerator is null");
        }

        this.messageGenerator = messageGenerator;
    }

    @Override
    public Compliance next() {
        Compliance compliance = super.next();
        Consumer consumer = compliance.getConsumer();

        for (ComplianceReason reason : compliance.getStatus().getReasons()) {
            this.messageGenerator.setMessage(consumer, reason);
        }

        return compliance;
    }
}
