package com.enterprise.totp.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;


@Component
@ConfigurationProperties(prefix = "totp")
public class TotpProperties {

    
    private int timeStepSeconds = 30;

    
    private int skewWindow = 1;

    
    private String algorithm = "SHA1";

    
    private String issuerName = "EnterpriseIAM";

    private Encryption encryption = new Encryption();
    private Cache cache = new Cache();
    private Warmup warmup = new Warmup();

    public int getTimeStepSeconds() { return timeStepSeconds; }
    public void setTimeStepSeconds(int timeStepSeconds) { this.timeStepSeconds = timeStepSeconds; }

    public int getSkewWindow() { return skewWindow; }
    public void setSkewWindow(int skewWindow) { this.skewWindow = skewWindow; }

    public String getAlgorithm() { return algorithm; }
    public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }

    public String getIssuerName() { return issuerName; }
    public void setIssuerName(String issuerName) { this.issuerName = issuerName; }

    public Encryption getEncryption() { return encryption; }
    public void setEncryption(Encryption encryption) { this.encryption = encryption; }

    public Cache getCache() { return cache; }
    public void setCache(Cache cache) { this.cache = cache; }

    public Warmup getWarmup() { return warmup; }
    public void setWarmup(Warmup warmup) { this.warmup = warmup; }

    public static class Encryption {
        
        private String keyEnvVar = "TOTP_ENCRYPTION_KEY";

        public String getKeyEnvVar() { return keyEnvVar; }
        public void setKeyEnvVar(String keyEnvVar) { this.keyEnvVar = keyEnvVar; }
    }

    public static class Cache {
        
        private boolean eagerPreload = false;
        
        private int preloadLimit = 1000;

        public boolean isEagerPreload() { return eagerPreload; }
        public void setEagerPreload(boolean eagerPreload) { this.eagerPreload = eagerPreload; }

        public int getPreloadLimit() { return preloadLimit; }
        public void setPreloadLimit(int preloadLimit) { this.preloadLimit = preloadLimit; }
    }

    public static class Warmup {
        
        private boolean enabled = true;
        
        private int iterations = 1000;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }

        public int getIterations() { return iterations; }
        public void setIterations(int iterations) { this.iterations = iterations; }
    }
}

