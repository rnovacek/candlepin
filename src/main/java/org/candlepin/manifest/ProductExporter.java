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

import org.apache.commons.lang.StringUtils;
import org.candlepin.model.Consumer;
import org.candlepin.model.Entitlement;
import org.candlepin.model.Product;
import org.candlepin.model.ProductCertificate;
import org.candlepin.model.ProvidedProduct;
import org.candlepin.service.ProductServiceAdapter;
import org.codehaus.jackson.map.ObjectMapper;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * ProductExporter
 */
public class ProductExporter {
    private ProductServiceAdapter productAdapter;

    @Inject
    ProductExporter(ProductServiceAdapter adapter) {
        productAdapter = adapter;
    }

    public void export(ObjectMapper mapper, File baseDir, Consumer consumer)
        throws IOException {

        File productDir = new File(baseDir.getCanonicalPath(), "products");
        productDir.mkdir();

        Map<String, Product> products = new HashMap<String, Product>();
        for (Entitlement entitlement : consumer.getEntitlements()) {

            for (ProvidedProduct providedProduct : entitlement.getPool().
                getProvidedProducts()) {
                // Don't want to call the adapter if not needed, it can be expensive.
                if (!products.containsKey(providedProduct.getProductId())) {
                    products.put(providedProduct.getProductId(),
                        productAdapter.getProductById(providedProduct.getProductId()));
                }
            }

            // Don't forget the 'main' product!
            String productId = entitlement.getPool().getProductId();
            if (!products.containsKey(productId)) {
                products.put(productId, productAdapter.getProductById(productId));
            }
        }

        for (Product product : products.values()) {
            String path = productDir.getCanonicalPath();
            String productId = product.getId();
            File file = new File(path, productId + ".json");
            FileWriter writer = new FileWriter(file);
            mapper.writeValue(writer, product);
            writer.close();

            // Real products have a numeric id.
            if (StringUtils.isNumeric(product.getId())) {
                ProductCertificate cert = productAdapter.getProductCertificate(product);
                // XXX: not all product adapters implement getProductCertificate,
                // so just skip over this if we get null back
                // XXX: need to decide if the cert should always be in the export, or never.
                if (cert != null) {
                    file = new File(productDir.getCanonicalPath(),
                        product.getId() + ".pem");
                    writer = new FileWriter(file);
                    writer.write(cert.getCert());
                    writer.close();
                }
            }
        }
    }

}
