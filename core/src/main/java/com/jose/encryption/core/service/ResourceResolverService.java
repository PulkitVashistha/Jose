package com.jose.encryption.core.service;

import org.apache.sling.api.resource.ResourceResolver;


public interface ResourceResolverService {
    /**
     * This method will fetch resource resolver.
     * User associated with this resolver is 'readServiceUser'
     *
     * @return ResourceResolver
     */

    String READ_SERVICE_USER = "readServiceUser";
    String WRITE_SERVICE_USER = "writeServiceUser";
    ResourceResolver getReadSystemResourceResolver();

    ResourceResolver getWriteSystemResourceResolver();
}
