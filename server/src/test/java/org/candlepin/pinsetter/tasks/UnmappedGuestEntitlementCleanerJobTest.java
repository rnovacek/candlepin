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

import static org.junit.Assert.*;

import org.candlepin.controller.PoolManager;
import org.candlepin.model.Consumer;
import org.candlepin.model.Entitlement;
import org.candlepin.model.EntitlementCurator;
import org.candlepin.model.Owner;
import org.candlepin.model.OwnerCurator;
import org.candlepin.model.Pool;
import org.candlepin.model.PoolAttribute;
import org.candlepin.model.PoolCurator;
import org.candlepin.model.PoolFilterBuilder;
import org.candlepin.model.Product;
import org.candlepin.test.DatabaseTestFixture;
import org.candlepin.test.TestUtil;

import org.junit.Test;

import java.util.Date;
import java.util.List;

import javax.inject.Inject;


public class UnmappedGuestEntitlementCleanerJobTest extends DatabaseTestFixture {

    @Inject private UnmappedGuestEntitlementCleanerJob job;
    @Inject private OwnerCurator ownerCurator;
    @Inject private PoolCurator poolCurator;
    @Inject private EntitlementCurator entitlementCurator;
    @Inject private PoolManager poolManager;

    @Test
    public void testToExecute() throws Exception {
        Product product = TestUtil.createProduct();

        Owner owner1 = createOwner();
        ownerCurator.create(owner1);

        Owner owner2 = createOwner();
        ownerCurator.create(owner2);

        Pool p1 = TestUtil.createPool(owner1, product);
        Pool p2 = TestUtil.createPool(owner2, product);

        p1.addAttribute(new PoolAttribute("unmapped_guest_only", "true"));
        p2.addAttribute(new PoolAttribute("unmapped_guest_only", "true"));

        poolManager.createPool(p1);
        poolManager.createPool(p2);

        Date thirtySixHoursAgo = new Date(new Date().getTime() - 36L * 60L * 60L * 1000L);
        Date twelveHoursAgo =  new Date(new Date().getTime() - 12L * 60L * 60L * 1000L);

        Entitlement e;
        Consumer c;

        c = createConsumer(owner1);
        c.setCreated(thirtySixHoursAgo);

        e = createEntitlement(owner1, c, p1, null);
        e.setQuantity(1);
        entitlementCurator.create(e);

        c = createConsumer(owner2);
        c.setCreated(twelveHoursAgo);

        e = createEntitlement(owner2, c, p2, null);
        e.setQuantity(1);
        entitlementCurator.create(e);

        poolCurator.refresh(p1);
        poolCurator.refresh(p2);

        job.execute(null);

        PoolFilterBuilder filters = new PoolFilterBuilder();
        filters.addAttributeFilter("unmapped_guest_only", "true");

        List<Pool> results = poolCurator.listByFilter(filters);
        assertEquals(2, results.size());

        int entitlements = 0;

        for (Pool p : results) {
            entitlements += p.getEntitlements().size();
            assertTrue(p.hasAttribute("unmapped_guest_only"));
        }

        assertEquals(1, entitlements);
    }
}
