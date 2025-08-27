package com.payshield.frauddetector.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix="app")
public class AppProperties {
    private Storage storage = new Storage();
    public Storage getStorage(){ return storage; }

    public static class Storage {
        private String basePath = "var/storage";
        public String getBasePath(){ return basePath; }
        public void setBasePath(String basePath){ this.basePath = basePath; }
    }
}
