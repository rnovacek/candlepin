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
package org.candlepin.jackson;

import java.util.HashSet;
import java.util.Set;

import org.apache.log4j.Logger;
import org.codehaus.jackson.map.ser.BeanPropertyFilter;
import org.codehaus.jackson.map.ser.impl.SimpleFilterProvider;

import com.google.inject.Inject;
import com.google.inject.servlet.RequestScoped;

/**
 * DynamicFilterProvider
 */
@RequestScoped
public class DynamicFilterProvider extends SimpleFilterProvider {

    private Set<String> attributes;
    private boolean blacklist;

    private static Logger log = Logger.getLogger(DynamicPropertyFilter.class);

    @Inject
    public DynamicFilterProvider() {
        this.attributes = new HashSet<String>();
        this.blacklist = false;
    }

    public BeanPropertyFilter findFilter(Object arg0) {
        log.info("Finding filter for: " + arg0);
        // TODO: this is where we'd do some magic filter configuration using the attributes
        // we already know about at this point:
        return super.findFilter(arg0);
    }

    public Set<String> getAttributes() {
        return attributes;
    }

    public void addAttribute(String attribute) {
        this.attributes.add(attribute);
    }

    public boolean isBlacklist() {
        return blacklist;
    }

    public void setBlacklist(boolean blacklist) {
        this.blacklist = blacklist;
    }

}
