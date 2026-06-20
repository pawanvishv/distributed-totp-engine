package com.enterprise.totp.infrastructure.base32;


public class Base32Codec {

    private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final char PADDING = '=';

    private Base32Codec() {}

    
    public static String encode(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        int buffer = 0;
        int bitsLeft = 0;

        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                bitsLeft -= 5;
                sb.append(BASE32_ALPHABET.charAt((buffer >> bitsLeft) & 0x1F));
            }
        }

        if (bitsLeft > 0) {
            buffer <<= (5 - bitsLeft);
            sb.append(BASE32_ALPHABET.charAt(buffer & 0x1F));
        }
        while (sb.length() % 8 != 0) {
            sb.append(PADDING);
        }

        return sb.toString();
    }

    
    public static byte[] decode(String encoded) {
        if (encoded == null || encoded.isEmpty()) {
            return new byte[0];
        }

        String normalized = encoded.toUpperCase().replace("=", "");
        int[] lookupTable = buildLookupTable();

        int outputLength = (normalized.length() * 5) / 8;
        byte[] result = new byte[outputLength];

        int buffer = 0;
        int bitsLeft = 0;
        int outIdx = 0;

        for (char c : normalized.toCharArray()) {
            int value = lookupTable[c];
            if (value < 0) {
                throw new IllegalArgumentException(
                        "Invalid Base32 character: '" + c + "' (0x" + Integer.toHexString(c) + ")");
            }
            buffer = (buffer << 5) | value;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                bitsLeft -= 8;
                result[outIdx++] = (byte) ((buffer >> bitsLeft) & 0xFF);
            }
        }

        return result;
    }

    private static int[] buildLookupTable() {
        int[] table = new int[128];
        java.util.Arrays.fill(table, -1);
        for (int i = 0; i < BASE32_ALPHABET.length(); i++) {
            table[BASE32_ALPHABET.charAt(i)] = i;
        }
        return table;
    }
}

