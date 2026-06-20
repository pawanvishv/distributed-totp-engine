package com.enterprise.totp.domain.replay;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ConcurrentHashMap;


public class InMemoryReplayCache implements ReplayCache {

    private static final Logger log = LoggerFactory.getLogger(InMemoryReplayCache.class);

    private final ConcurrentHashMap<String, Boolean> usedCodes = new ConcurrentHashMap<>();

    @Override
    public boolean markUsed(String userId, String code, long timeStep) {
        String compositeKey = userId + ":" + code + ":" + timeStep;
        return usedCodes.putIfAbsent(compositeKey, Boolean.TRUE) == null;
    }

    @Override
    public void evictBefore(long thresholdStep) {
        usedCodes.entrySet().removeIf(entry -> {
            try {
                String[] parts = entry.getKey().split(":");
                if (parts.length < 3) {
                    log.warn("replay.cache.eviction.malformed_key: {}", entry.getKey());
                    return false; // keep malformed keys, do not crash eviction
                }
                long entryStep = Long.parseLong(parts[parts.length - 1]);
                return entryStep < thresholdStep;
            } catch (NumberFormatException e) {
                log.warn("replay.cache.eviction.malformed_key: cannot parse step from key={}",
                        entry.getKey());
                return false; // keep rather than crash the eviction task
            }
        });
    }

    @Override
    public int cacheSize() {
        return usedCodes.size();
    }
}

