package com.jose.encryption.core.service.impl;

import com.jose.encryption.core.service.ResourceResolverService;
import org.apache.sling.api.resource.LoginException;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

@Component(service = ResourceResolverService.class, immediate = true, name = "Admin resource resolver", configurationPolicy = ConfigurationPolicy.OPTIONAL)
public class ResourceResolverImpl implements ResourceResolverService {

    private final Logger log = LoggerFactory.getLogger(this.getClass());

    @Reference
    private ResourceResolverFactory resourceFactory;

    public ResourceResolver getReadSystemResourceResolver() {
        ResourceResolver resourceResolver = null;
        try {
            Map<String, Object> paramMap = new HashMap<String, Object>();
            paramMap.put(ResourceResolverFactory.SUBSERVICE, ResourceResolverService.READ_SERVICE_USER);
            resourceResolver = resourceFactory.getServiceResourceResolver(paramMap);
        } catch (LoginException e) {
            log.error("Login Exception : " + e);
        }
        return resourceResolver;
    }

    public ResourceResolver getWriteSystemResourceResolver() {
        ResourceResolver resourceResolver = null;
        try {
            Map<String, Object> paramMap = new HashMap<String, Object>();
            paramMap.put(ResourceResolverFactory.SUBSERVICE, ResourceResolverService.WRITE_SERVICE_USER);
            resourceResolver = resourceFactory.getServiceResourceResolver(paramMap);
        } catch (LoginException e) {
            log.error("Login Exception : " + e);
        }
        return resourceResolver;
    }

}
