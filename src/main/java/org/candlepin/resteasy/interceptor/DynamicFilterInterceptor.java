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
package org.candlepin.resteasy.interceptor;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.ext.Provider;

import org.candlepin.jackson.DynamicFilterable;
import org.jboss.resteasy.annotations.interception.ServerInterceptor;
import org.jboss.resteasy.core.ResourceMethod;
import org.jboss.resteasy.core.ServerResponse;
import org.jboss.resteasy.spi.Failure;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.interception.PostProcessInterceptor;
import org.jboss.resteasy.spi.interception.PreProcessInterceptor;

/**
 * DynamicFilterInterceptor
 */
@Provider
@ServerInterceptor
public class DynamicFilterInterceptor implements PreProcessInterceptor, PostProcessInterceptor {

    private static ThreadLocal<Set<String>> blacklist = new ThreadLocal<Set<String>>();
    private static ThreadLocal<Set<String>> whitelist = new ThreadLocal<Set<String>>();

    @Override
    public ServerResponse preProcess(HttpRequest request, ResourceMethod method)
        throws Failure, WebApplicationException {
        blacklist.set(new HashSet<String>());
        whitelist.set(new HashSet<String>());
        Map<String, List<String>> queryParams = request.getUri().getQueryParameters();
        if (queryParams.containsKey("exclude")) {
            for (String toExclude : queryParams.get("exclude")) {
                blacklist.get().add(toExclude);
            }
        }
        if (queryParams.containsKey("include")) {
            for (String toInclude : queryParams.get("include")) {
                whitelist.get().add(toInclude);
            }
        }
        return null;
    }

    @Override
    public void postProcess(ServerResponse response) {
        Object obj = response.getEntity();
        int blsize = blacklist.get() != null ? blacklist.get().size() : -1;
        this.addFilters(obj);
    }
    
    private void addFilters(Object obj) {
        if (obj instanceof Collection) {
            Collection<?> collection = (Collection<?>) obj;
            for (Object o : collection) {
                addFilters(o);
            }
        }
        if (obj instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) obj;
            for (Object o : map.keySet()) {
                addFilters(o);
                addFilters(map.get(o));
            }
        }
        else if (obj instanceof DynamicFilterable) {
            //If the object is dynamically filterable, add filter options
            DynamicFilterable df = (DynamicFilterable) obj;
            for (String allow : whitelist.get()) {
                df.allowAttribute(allow);
            }
            // Apply blacklist second, if attributes are found in both,
            // this will remove them from the objects whitelist
            for (String filter : blacklist.get()) {
                df.filterAttribute(filter);
            }
        }
    }
}