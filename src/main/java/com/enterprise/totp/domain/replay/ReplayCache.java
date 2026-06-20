package com.enterprise.totp.domain.replay;


public interface ReplayCache {

    
    boolean markUsed(String userId, String code, long timeStep);

    
    void evictBefore(long thresholdStep);

    
    int cacheSize();
}

