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

package org.candlepin.service.impl;

import org.candlepin.model.Consumer;
import org.candlepin.model.Owner;
import org.candlepin.model.Product;
import org.candlepin.model.Subscription;
import org.candlepin.service.SubscriptionServiceAdapter;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * A subscription service adapter used by the importer. This adapter is used to
 * provide a non-persisted collection of Subscriptions that are to be converted
 * to pools.
 *
 */
public class ImportSubscriptionServiceAdapter implements
        SubscriptionServiceAdapter {

    private Map<String, Subscription> subsBySubId;

    public ImportSubscriptionServiceAdapter(List<Subscription> subs) {
        for (Subscription sub : subs) {
            subsBySubId.put(sub.getId(), sub);
        }
    }

    @Override
    public List<Subscription> getSubscriptions(Owner owner) {
        List<Subscription> subs = new LinkedList<Subscription>();
        for (Subscription sub : getSubscriptions()) {
            if (sub.getOwner().equals(owner)) {
                subs.add(sub);
            }
        }
        return subs;
    }

    @Override
    public List<String> getSubscriptionIds(Owner owner) {
        List<String> subIds = new LinkedList<String>();
        for (Subscription sub : getSubscriptions(owner)) {
            subIds.add(sub.getId());
        }
        return subIds;
    }

    @Override
    public Subscription getSubscription(String subscriptionId) {
        return this.subsBySubId.get(subscriptionId);
    }

    @Override
    public List<Subscription> getSubscriptions() {
        return new ArrayList<Subscription>(subsBySubId.values());
    }

    @Override
    public void activateSubscription(Consumer consumer, String email,
            String emailLocale) {
    }

    @Override
    public Subscription createSubscription(Subscription s) {
        return s;
    }

    @Override
    public void deleteSubscription(Subscription s) {
        subsBySubId.remove(s.getId());
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean hasUnacceptedSubscriptionTerms(Owner owner) {
        return false;
    }

    @Override
    public void sendActivationEmail(String subscriptionId) {
        // hosted-only
    }

    @Override
    public boolean canActivateSubscription(Consumer consumer) {
        return false;
    }

    @Override
    public List<Subscription> getSubscriptions(Product product) {
        List<Subscription> subs = new LinkedList<Subscription>();
        for (Subscription sub : getSubscriptions()) {
            if (product.getId().equals(sub.getProduct().getId())) {
                subs.add(sub);
                continue;
            }

            for (Product p : sub.getProvidedProducts()) {
                if (product.getId().equals(p.getId())) {
                    subs.add(sub);
                    break;
                }
            }
        }
        return subs;
    }

}
