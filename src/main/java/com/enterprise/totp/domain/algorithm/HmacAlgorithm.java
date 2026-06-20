package com.enterprise.totp.domain.algorithm;


public enum HmacAlgorithm {

    SHA1("HmacSHA1", "SHA1", 20),
    SHA256("HmacSHA256", "SHA256", 32),
    SHA512("HmacSHA512", "SHA512", 64);

    private final String jcaName;
    private final String uriName;
    private final int outputBytes;

    HmacAlgorithm(String jcaName, String uriName, int outputBytes) {
        this.jcaName = jcaName;
        this.uriName = uriName;
        this.outputBytes = outputBytes;
    }

    
    public String jcaName() {
        return jcaName;
    }

    
    public String uriName() {
        return uriName;
    }

    
    public int outputBytes() {
        return outputBytes;
    }

    
    public static HmacAlgorithm fromName(String name) {
        for (HmacAlgorithm alg : values()) {
            if (alg.jcaName.equalsIgnoreCase(name) || alg.uriName.equalsIgnoreCase(name)) {
                return alg;
            }
        }
        throw new IllegalArgumentException("Unknown HMAC algorithm: " + name);
    }
}

