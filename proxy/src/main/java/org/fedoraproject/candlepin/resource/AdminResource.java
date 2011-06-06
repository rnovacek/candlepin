/**
 * Copyright (c) 2009 Red Hat, Inc.
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
package org.fedoraproject.candlepin.resource;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.apache.log4j.Logger;
import org.fedoraproject.candlepin.model.ConsumerType;
import org.fedoraproject.candlepin.model.ConsumerTypeCurator;
import org.fedoraproject.candlepin.model.Owner;
import org.fedoraproject.candlepin.model.OwnerCurator;
import org.fedoraproject.candlepin.model.OwnerPermission;
import org.fedoraproject.candlepin.model.Role;
import org.fedoraproject.candlepin.model.RoleCurator;
import org.fedoraproject.candlepin.model.User;
import org.fedoraproject.candlepin.model.ConsumerType.ConsumerTypeEnum;
import org.fedoraproject.candlepin.service.UserServiceAdapter;

import com.google.inject.Inject;

import org.fedoraproject.candlepin.auth.Access;
import org.fedoraproject.candlepin.auth.Principal;
import org.fedoraproject.candlepin.auth.SystemPrincipal;
import org.fedoraproject.candlepin.auth.interceptor.SecurityHole;
import org.jboss.resteasy.spi.ResteasyProviderFactory;

/**
 * Candlepin server administration REST calls.
 */
@Path("/admin")
public class AdminResource {

    private static Logger log = Logger.getLogger(AdminResource.class);
    
    private ConsumerTypeCurator consumerTypeCurator;
    private UserServiceAdapter userService;
    private RoleCurator roleCurator;
    private OwnerCurator ownerCurator;

    @Inject
    public AdminResource(ConsumerTypeCurator consumerTypeCurator,
            UserServiceAdapter userService, RoleCurator roleCurator,
            OwnerCurator ownerCurator) {
        this.consumerTypeCurator = consumerTypeCurator;
        this.userService = userService;
        this.roleCurator = roleCurator;
        this.ownerCurator = ownerCurator;
    }

    /**
     * Initialize the Candlepin database.
     * 
     * Currently this just creates static'ish database entries for things like
     * consumer types. This call needs to happen once after a database is created.
     * Repeated calls are not required, but will be harmless.
     * 
     * @return Description if db was or already is initialized.
     */
    @GET
    @Produces({MediaType.TEXT_PLAIN})
    @Path("init")
    @SecurityHole
    public String initialize() {
        log.debug("Called initialize()");

        // First, determine if we've already setup the DB and if so, do *nothing*!
        ConsumerType systemType = consumerTypeCurator.lookupByLabel(
            ConsumerTypeEnum.SYSTEM.getLabel());
        if (systemType != null) {
            log.info("Database already initialized.");
            return "Already initialized.";
        }
        log.info("Initializing Candlepin database.");

        // Push the system principal so we can create all these entries as a superuser
        ResteasyProviderFactory.pushContext(Principal.class, new SystemPrincipal());

        for (ConsumerTypeEnum type : ConsumerTypeEnum.values()) {
            ConsumerType created = new ConsumerType(type); 
            consumerTypeCurator.create(created);
            log.debug("Created: " + created);
        }

        log.info("Creating default super admin.");
        try {
            User defaultAdmin = new User("admin", "admin", true);
            userService.createUser(defaultAdmin);

            Owner o = new Owner("admin-test", "admin test");
            ownerCurator.create(o);

            Role adminRole = new Role();
            adminRole.addUser(defaultAdmin);
            adminRole.addPermission(new OwnerPermission(o,
                Access.ALL));
            roleCurator.create(adminRole);
        } 
        catch (UnsupportedOperationException e) {
            log.info("Admin creation is not supported!");
        }

        return "Initialized!";
    }
}
