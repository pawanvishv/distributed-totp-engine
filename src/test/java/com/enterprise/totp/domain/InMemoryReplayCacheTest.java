package com.enterprise.totp.domain;

import com.enterprise.totp.domain.replay.InMemoryReplayCache;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class InMemoryReplayCacheTest {

    private InMemoryReplayCache cache;

    @BeforeEach
    void setUp() {
        cache = new InMemoryReplayCache();
    }

    @Test
    void firstMarkUsedReturnsTrue() {
        assertThat(cache.markUsed("alice", "123456", 55L)).isTrue();
    }

    @Test
    void secondIdenticalMarkUsedReturnsFalse() {
        cache.markUsed("alice", "123456", 55L);
        assertThat(cache.markUsed("alice", "123456", 55L)).isFalse();
    }

    @Test
    void sameCodeDifferentTimeStepBothAccepted() {
        assertThat(cache.markUsed("alice", "123456", 55L)).isTrue();
        assertThat(cache.markUsed("alice", "123456", 56L)).isTrue();
    }

    @Test
    void sameCodeDifferentUserBothAccepted() {
        assertThat(cache.markUsed("alice", "123456", 55L)).isTrue();
        assertThat(cache.markUsed("bob", "123456", 55L)).isTrue();
    }

    @Test
    void cacheSizeReflectsEntryCount() {
        cache.markUsed("alice", "111111", 1L);
        cache.markUsed("bob", "222222", 2L);
        assertThat(cache.cacheSize()).isEqualTo(2);
    }

    @Test
    void evictBeforeRemovesExpiredEntries() {
        cache.markUsed("alice", "123456", 10L);
        cache.markUsed("bob", "654321", 20L);
        cache.markUsed("carol", "111111", 30L);

        cache.evictBefore(20L); // removes step < 20 â†’ removes step 10
        assertThat(cache.markUsed("alice", "123456", 10L)).isTrue();
        assertThat(cache.markUsed("bob", "654321", 20L)).isFalse();
        assertThat(cache.markUsed("carol", "111111", 30L)).isFalse();
    }

    @Test
    void evictBeforeWithHighThresholdClearsAllExpired() {
        cache.markUsed("alice", "123456", 5L);
        cache.markUsed("bob", "654321", 10L);

        cache.evictBefore(100L);
        assertThat(cache.cacheSize()).isZero();
    }

    @RepeatedTest(20)
    void concurrency200ThreadsOnlyOneSucceeds() throws Exception {
        int threadCount = 200;
        CyclicBarrier barrier = new CyclicBarrier(threadCount);
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        AtomicInteger successCount = new AtomicInteger(0);
        List<Future<?>> futures = new ArrayList<>();

        for (int i = 0; i < threadCount; i++) {
            futures.add(executor.submit(() -> {
                try {
                    barrier.await();
                    if (cache.markUsed("concurrent_user", "999999", 1L)) {
                        successCount.incrementAndGet();
                    }
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }));
        }

        for (Future<?> f : futures) {
            f.get();
        }
        executor.shutdown();

        assertThat(successCount.get()).isEqualTo(1);
    }
}

