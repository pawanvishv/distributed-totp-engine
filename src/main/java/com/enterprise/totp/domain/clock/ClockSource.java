package com.enterprise.totp.domain.clock;


@FunctionalInterface
public interface ClockSource {

    
    long currentTimeMillis();
}

