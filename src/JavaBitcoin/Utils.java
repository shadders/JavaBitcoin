/**
 * Copyright 2011 Google Inc.
 * Copyright 2013 Ronald W Hoffman
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package JavaBitcoin;

import org.bouncycastle.crypto.digests.RIPEMD160Digest;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.math.BigDecimal;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Static utility methods
 */
public class Utils {

    /** Constant -1 */
    public static final BigInteger NEGATIVE_ONE = BigInteger.valueOf(-1);

    /** Constant 1,000 */
    private static final BigInteger DISPLAY_1K = new BigInteger("1000");

    /** Constant 1,000,000 */
    private static final BigInteger DISPLAY_1M = new BigInteger("1000000");

    /** Constant 1,000,000,000 */
    private static final BigInteger DISPLAY_1G = new BigInteger("1000000000");

    /** Constant 1,000,000,000,000 */
    private static final BigInteger DISPLAY_1T = new BigInteger("1000000000000");

    /** Constant 1,000,000,000,000,000 */
    private static final BigInteger DISPLAY_1P = new BigInteger("1000000000000000");

    /** Bit masks (Low-order bit is bit 0 and high-order bit is bit 7) */
    private static final int bitMask[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};

    /** Instance of a SHA-256 digest which we will use as needed */
    private static final MessageDigest digest;
    static {
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);  // Can't happen.
        }
    }

    /**
     * How many "nanocoins" there are in a Bitcoin.
     *
     * A nanocoin is the smallest unit that can be transferred using Bitcoin.
     * The term nanocoin is very misleading, though, because there are only 100 million
     * of them in a coin (whereas one would expect 1 billion.
     */
    public static final BigInteger COIN = new BigInteger("100000000", 10);

    /**
     * How many "nanocoins" there are in 0.01 BitCoins.
     *
     * A nanocoin is the smallest unit that can be transferred using Bitcoin.
     * The term nanocoin is very misleading, though, because there are only 100 million
     * of them in a coin (whereas one would expect 1 billion).
     */
    public static final BigInteger CENT = new BigInteger("1000000", 10);

    /**
     * Calculate the SHA-256 hash of the input
     *
     * @param       input           Data to be hashed
     * @return                      The hash digest
     */
    public static byte[] singleDigest(byte[] input) {
        return singleDigest(input, 0, input.length);
    }

    /**
     * Calculate the SHA-256 hash of the input
     *
     * @param       input           Data to be hashed
     * @param       offset          Starting offset within the data
     * @param       length          Number of bytes to hash
     * @return                      The hash digest
     */
    public static byte[] singleDigest(byte[] input, int offset, int length) {
        synchronized (digest) {
            digest.reset();
            digest.update(input, offset, length);
            return digest.digest();
        }
    }

    /**
     * Calculate the SHA-256 hash of the input and then hash the resulting hash again
     *
     * @param       input           Data to be hashed
     * @return                      The hash digest
     */
    public static byte[] doubleDigest(byte[] input) {
        return doubleDigest(input, 0, input.length);
    }

    /**
     * Calculate the SHA-256 hash of the input and then hash the resulting hash again
     *
     * @param       input           Data to be hashed
     * @param       offset          Starting offset within the data
     * @param       length          Number of data bytes to hash
     * @return                      The hash digest
     */
    public static byte[] doubleDigest(byte[] input, int offset, int length) {
        synchronized (digest) {
            digest.reset();
            digest.update(input, offset, length);
            byte[] first = digest.digest();
            return digest.digest(first);
        }
    }

    /**
     * Calculate SHA256(SHA256(byte range 1 + byte range 2)).
     *
     * @param       input1          First input byte array
     * @param       offset1         Starting position in the first array
     * @param       length1         Number of bytes to process in the first array
     * @param       input2          Second input byte array
     * @param       offset2         Starting position in the second array
     * @param       length2         Number of bytes to process in the second array
     * @return                      The SHA-256 digest
     */
    public static byte[] doubleDigestTwoBuffers(byte[]input1, int offset1, int length1,
                                                byte[]input2, int offset2, int length2) {
        synchronized (digest) {
            digest.reset();
            digest.update(input1, offset1, length1);
            digest.update(input2, offset2, length2);
            byte[]first = digest.digest();
            return digest.digest(first);
        }
    }

    /**
     * Return the given byte array encoded as a hex string
     *
     * @param       bytes           The data to be encoded
     * @return                      The encoded string
     */
    public static String bytesToHexString(byte[] bytes) {
        StringBuilder buf = new StringBuilder(bytes.length*2);
        for (byte b : bytes) {
            String s = Integer.toString(0xFF&b, 16);
            if (s.length() < 2)
                buf.append('0');

            buf.append(s);
        }
        return buf.toString();
    }

    /**
     * Returns a string representing the shortened numeric value.  For example,
     * the value 1,500,000 will be returned as 1.500M.
     *
     * @param       number          The number to be displayed
     * @return      Display string
     */
    public static String numberToShortString(BigInteger number) {
        int scale;
        String suffix;
        BigDecimal work;
        if (number.compareTo(DISPLAY_1P) >= 0) {
            scale = 15;
            suffix = "P";
        } else if (number.compareTo(DISPLAY_1T) >= 0) {
            scale = 12;
            suffix = "T";
        } else if (number.compareTo(DISPLAY_1G) >= 0) {
            scale = 9;
            suffix = "G";
        } else if (number.compareTo(DISPLAY_1M) >= 0) {
            scale = 6;
            suffix = "M";
        } else if (number.compareTo(DISPLAY_1K) >= 0) {
            scale = 3;
            suffix = "K";
        } else {
            scale = 0;
            suffix = "";
        }
        if (scale != 0)
            work = new BigDecimal(number, scale);
        else
            work = new BigDecimal(number);

        return String.format("%3.3f%s", work.floatValue(), suffix);
    }

    /**
     * Checks if the specified bit is set
     *
     * @param       data            Byte array to check
     * @param       index           Bit position
     * @return      TRUE if the bit is set
     */
    public static boolean checkBitLE(byte[] data, int index) {
        return (data[index>>>3] & bitMask[7&index]) != 0;
    }

    /**
     * Sets the specified bit
     * @param       data            Byte array
     * @param       index           Bit position
     */
    public static void setBitLE(byte[] data, int index) {
        data[index>>>3] |= bitMask[7&index];
    }
    
    /**
     * The representation of nBits uses another home-brew encoding, as a way to represent a large
     * hash value in only 32 bits.
     *
     * @param       compact         The compact bit representation
     * @return                      The decoded result
     */
    public static BigInteger decodeCompactBits(long compact) {
        int size = ((int)(compact>>24)) & 0xFF;
        byte[] bytes = new byte[4 + size];
        bytes[3] = (byte)size;
        if (size>=1) bytes[4] = (byte)((compact>>16) & 0xFF);
        if (size>=2) bytes[5] = (byte)((compact>>8) & 0xFF);
        if (size>=3) bytes[6] = (byte)(compact & 0xFF);
        return decodeMPI(bytes, true);
    }

    /**
     * MPI encoded numbers are produced by the OpenSSL BN_bn2mpi function. They consist of
     * a 4 byte big-endian length field, followed by the stated number of bytes representing
     * the number in big-endian format (with a sign bit).
     *
     * @param       mpi             Encoded byte array
     * @param       hasLength       FALSE if the given array is missing the 4-byte length field
     * @return                      Decoded value
     */
    public static BigInteger decodeMPI(byte[] mpi, boolean hasLength) {
        byte[] buf;
        if (hasLength) {
            int length = (int)readUint32BE(mpi, 0);
            buf = new byte[length];
            System.arraycopy(mpi, 4, buf, 0, length);
        } else {
            buf = mpi;
        }
        if (buf.length == 0)
            return BigInteger.ZERO;
        boolean isNegative = (buf[0] & 0x80) == 0x80;
        if (isNegative)
            buf[0] &= 0x7f;
        BigInteger result = new BigInteger(buf);
        return isNegative ? result.negate() : result;
    }

    /**
     * Returns a copy of the given byte array in reverse order.
     *
     * @param       bytes           Array to be reversed
     * @return                      New byte array in reverse order
     */
    public static byte[] reverseBytes(byte[] bytes) {
        byte[] buf = new byte[bytes.length];
        for (int i=0; i<bytes.length; i++)
            buf[i] = bytes[bytes.length-1-i];
        return buf;
    }

    /**
     * Returns a copy of the given byte array in reverse order
     *
     * @param       bytes           Array to be reversed
     * @param       offset          Starting offset in the array
     * @param       length          Number of bytes to reverse
     * @return                      New byte array in reverse order
     */
    public static byte[] reverseBytes(byte[] bytes, int offset, int length) {
        byte[] buf = new byte[length];
        for (int i=0; i<length; i++)
            buf[i] = bytes[offset+length-1-i];
        return buf;
    }

    /**
     * Returns a copy of the given byte array with the bytes of each double-word (4 bytes) reversed.
     *
     * @param       bytes           Bytes to reverse (length must be divisible by 4)
     * @param       trimLength      Trim output to this length (If positive, must be divisible by 4)
     * @return                      Reversed bytes
     */
    public static byte[] reverseDwordBytes(byte[] bytes, int trimLength) {
        byte[] rev = new byte[trimLength >= 0 && bytes.length > trimLength ? trimLength : bytes.length];
        for (int i = 0; i < rev.length; i += 4) {
            System.arraycopy(bytes, i, rev, i , 4);
            for (int j = 0; j < 4; j++) {
                rev[i + j] = bytes[i + 3 - j];
            }
        }
        return rev;
    }

    /**
     * Form an integer value from an 2-byte array in big-endian format
     *
     * @param       bytes           The byte array
     * @param       offset          Starting offset within the array
     * @return      The decoded value
     */
    public static int readUint16BE(byte[] bytes, int offset) {
        return (((int)bytes[offset++]&0x00ff) << 8) |
               ((int)bytes[offset]&0x00ff);
    }

    /**
     * Form a long value from a 4-byte array in little-endian format
     *
     * @param       bytes           The byte array
     * @param       offset          Starting offset within the array
     * @return      The decoded value
     */
    public static long readUint32LE(byte[] bytes, int offset) {
        return ((long)bytes[offset++]&0x00FFL) |
               (((long)bytes[offset++]&0x00FFL) << 8) |
               (((long)bytes[offset++]&0x00FFL) << 16) |
               (((long)bytes[offset]&0x00FFL) << 24);
    }

    /**
     * Form a long value from a 4-byte array in big-endian format
     *
     * @param       bytes           The byte array
     * @param       offset          Starting offset within the array
     * @return                      The long value
     */
    public static long readUint32BE(byte[] bytes, int offset) {
        return (((long)bytes[offset++]&0x00FFL) << 24) |
                (((long)bytes[offset++]&0x00FFL) << 16) |
                (((long)bytes[offset++]&0x00FFL) << 8) |
                ((long)bytes[offset]&0x00FFL);
    }

    /**
     * Write an unsigned 32-bit value to a byte array in little-endian format
     *
     * @param       val             Value to be written
     * @param       out             Output array
     * @param       offset          Starting offset
     */
    public static void uint32ToByteArrayLE(long val, byte[] out, int offset) {
        out[offset++] = (byte)val;
        out[offset++] = (byte)(val >> 8);
        out[offset++] = (byte)(val >> 16);
        out[offset] = (byte)(val >> 24);
    }

    /**
     * Write an unsigned 32-bit value to a byte array in big-endian format
     *
     * @param       val             Value to be written
     * @param       out             Output array
     * @param       offset          Starting offset
     */
    public static void uint32ToByteArrayBE(long val, byte[] out, int offset) {
        out[offset++] = (byte)(val>>24);
        out[offset++] = (byte)(val>>16);
        out[offset++] = (byte)(val>>8);
        out[offset] = (byte)val;
    }

    /**
     * Write an unsigned 32-bit value to an output stream in little-endian format
     *
     * @param       val             Value to be written
     * @param       stream          Output stream
     *
     * @throws                      IOException
     */
    public static void uint32ToByteStreamLE(long val, OutputStream stream) throws IOException {
        stream.write((int)(0x00FF&val));
        stream.write((int)(0x00FF&(val >> 8)));
        stream.write((int)(0x00FF&(val >> 16)));
        stream.write((int)(0x00FF&(val >> 24)));
    }

    /**
     * Form a long value from an 8-byte array in little-endian format
     *
     * @param       bytes           The byte array
     * @param       offset          Starting offset within the array
     * @return                      The long value
     */
    public static long readUint64LE(byte[] bytes, int offset) {
        return ((long)bytes[offset++]&0x00FFL) |
               (((long)bytes[offset++]&0x00FFL) << 8) |
               (((long)bytes[offset++]&0x00FFL) << 16) |
               (((long)bytes[offset++]&0x00FFL) << 24) |
               (((long)bytes[offset++]&0x00FFL) << 32) |
               (((long)bytes[offset++]&0x00FFL) << 40) |
               (((long)bytes[offset++]&0x00FFL) << 48) |
               (((long)bytes[offset]&0x00FFL) << 56);
    }

    /**
     * Write an unsigned 64-bit value to a byte array in little-endian format
     *
     * @param       val             Value to be written
     * @param       out             Output array
     * @param       offset          Starting offset
     */
    public static void uint64ToByteArrayLE(long val, byte[] out, int offset) {
        out[offset++] = (byte)val;
        out[offset++] = (byte)(val >> 8);
        out[offset++] = (byte)(val >> 16);
        out[offset++] = (byte)(val >> 24);
        out[offset++] = (byte)(val >> 32);
        out[offset++] = (byte)(val >> 40);
        out[offset++] = (byte)(val >> 48);
        out[offset] = (byte)(val >> 56);
    }

    /**
     * Write a 64-bit value to a byte stream in little-endian format
     *
     * @param       val             The value to be written
     * @param       stream          The output stream
     * @throws      IOException
     */
    public static void uint64ToByteStreamLE(long val, OutputStream stream) throws IOException {
        stream.write((int)(0x00FF&val));
        stream.write((int)(0x00FF&(val >> 8)));
        stream.write((int)(0x00FF&(val >> 16)));
        stream.write((int)(0x00FF&(val >> 24)));
        stream.write((int)(0x00FF&(val >> 32)));
        stream.write((int)(0x00FF&(val >> 40)));
        stream.write((int)(0x00FF&(val >> 48)));
        stream.write((int)(0x00FF&(val >> 56)));
    }

    /**
     * Write a BigInteger value to a byte stream in little-endian format
     *
     * @param       val             BigInteger to be written
     * @param       stream          Output stream
     * @throws      IOException
     */
    public static void uint64ToByteStreamLE(BigInteger val, OutputStream stream) throws IOException {
        byte[] bytes = val.toByteArray();
        if (bytes.length > 8)
            throw new RuntimeException("Input too large to encode into a uint64");
        bytes = reverseBytes(bytes);
        stream.write(bytes);
        if (bytes.length < 8) {
            for (int i=0; i<8-bytes.length; i++)
                stream.write(0);
        }
    }

    /**
     * Calculate RIPEMD160(SHA256(input)).  This is used in Address calculations.
     *
     * @param       input           The byte array to be hashed
     * @return                      The hashed result
     */
    public static byte[] sha256Hash160(byte[] input) {
        byte[] out = new byte[20];
        synchronized(digest) {
            digest.reset();
            byte[] sha256 = digest.digest(input);
            RIPEMD160Digest rDigest = new RIPEMD160Digest();
            rDigest.update(sha256, 0, sha256.length);
            rDigest.doFinal(out, 0);
        }
        return out;
    }
}
