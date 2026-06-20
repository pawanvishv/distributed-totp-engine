package com.enterprise.totp.domain.algorithm;


public interface TotpStrategy {

    
    String generateCode(byte[] secret, long counter);
}

