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
package org.candlepin.pinsetter.tasks;

import org.candlepin.model.Entitlement;
import org.candlepin.model.EntitlementCurator;
import org.candlepin.model.Pool;
import org.candlepin.model.PoolCurator;
import org.candlepin.model.PoolFilterBuilder;

import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.inject.Inject;

/**
 *
 * UnmappedGuestEntitlementCleanerJob removes 24 hour unmapped guest entitlements
 * after the entitlement has expired.  Entitlements normally last until to pool expires
 */
public class UnmappedGuestEntitlementCleanerJob extends KingpinJob {
    // Run at 3 AM and every 12 hours afterwards
    public static final String DEFAULT_SCHEDULE = "0 0 3/12 * * ?";

    private PoolCurator poolCurator;
    private EntitlementCurator entitlementCurator;

    @Inject
    public UnmappedGuestEntitlementCleanerJob(PoolCurator poolCurator,
            EntitlementCurator entitlementCurator) {
        this.poolCurator = poolCurator;
        this.entitlementCurator = entitlementCurator;
    }

    @Override
    public void toExecute(JobExecutionContext context)
        throws JobExecutionException {
        Date now = new Date();
        PoolFilterBuilder filters = new PoolFilterBuilder();
        filters.addAttributeFilter("unmapped_guest_only", "true");

        List<Pool> unmappedGuestPools = poolCurator.listByFilter(filters);
        List<Entitlement> lapsedUnmappedGuestEntitlements = new ArrayList<Entitlement>();

        for (Pool p : unmappedGuestPools) {
            for (Entitlement e : p.getEntitlements()) {
                if (isLapsed(e, now)) {
                    lapsedUnmappedGuestEntitlements.add(e);
                }
            }
        }

        entitlementCurator.bulkDelete(lapsedUnmappedGuestEntitlements);
    }

    protected boolean isLapsed(Entitlement e, Date lapseDate) {
        return e.getEndDate().before(lapseDate);
    }
}
