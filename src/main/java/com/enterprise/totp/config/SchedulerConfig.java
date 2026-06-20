package com.enterprise.totp.config;

import com.enterprise.totp.domain.clock.ClockSource;
import com.enterprise.totp.domain.replay.ReplayCache;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.SmartLifecycle;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;


@Configuration
public class SchedulerConfig {

    private static final Logger log = LoggerFactory.getLogger(SchedulerConfig.class);

    @Bean
    public ScheduledExecutorService evictionExecutor() {
        return Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "totp-replay-cache-eviction");
            thread.setDaemon(true);
            return thread;
        });
    }

    @Bean
    public SmartLifecycle replayCacheEvictionLifecycle(ScheduledExecutorService evictionExecutor,
                                                        ReplayCache replayCache,
                                                        ClockSource clockSource,
                                                        TotpProperties properties,
                                                        MeterRegistry meterRegistry) {
        return new SmartLifecycle() {
            private volatile boolean running = false;

            @Override
            public void start() {
                long intervalSeconds = properties.getTimeStepSeconds();
                evictionExecutor.scheduleAtFixedRate(() -> {
                    try {
                        long currentStep = clockSource.currentTimeMillis()
                                / ((long) properties.getTimeStepSeconds() * 1000L);
                        long threshold = currentStep - (properties.getSkewWindow() + 1);
                        replayCache.evictBefore(threshold);

                        int size = replayCache.cacheSize();
                        meterRegistry.gauge("mfa.replay_cache.size", size);
                        log.debug("replay.cache.eviction: threshold={} size={}", threshold, size);
                    } catch (Exception e) {
                        log.error("replay.cache.eviction.error: Eviction cycle failed. " +
                                "Cache may grow unbounded if this persists.", e);
                        meterRegistry.counter("mfa.replay_cache.eviction.error").increment();
                    }
                }, 0, intervalSeconds, TimeUnit.SECONDS);
                running = true;
                log.info("replay.cache.eviction.started: interval={}s", intervalSeconds);
            }

            @Override
            public void stop() {
                evictionExecutor.shutdown();
                running = false;
                log.info("replay.cache.eviction.stopped");
            }

            @Override
            public boolean isRunning() {
                return running;
            }

            @Override
            public int getPhase() {
                return Integer.MAX_VALUE - 1; // stop last, after most beans
            }
        };
    }
}

