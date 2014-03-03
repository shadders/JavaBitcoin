/**
 * Copyright 2012 Matt Corallo
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

import java.io.EOFException;
import java.io.InputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * <p>A Bloom filter is a probabilistic data structure which can be sent to another client
 * so that it can avoid sending us transactions that aren't relevant to our set of keys.
 * This allows for significantly more efficient use of available network bandwidth and CPU time.</p>
 *
 * <p>Because a Bloom filter is probabilistic, it has a configurable false positive rate.
 * So the filter will sometimes match transactions that weren't inserted into it, but it will
 * never fail to match transactions that were. This is a useful privacy feature - if you have
 * spare bandwidth the false positive rate can be increased so the remote peer gets a noisy
 * picture of what transactions are relevant to your wallet.</p>
 *
 * <p>Bloom Filter</p>
 * <pre>
 *   Size       Field               Description
 *   ====       =====               ===========
 *   VarInt     Count               Number of bytes in the filter
 *   Variable   Filter              Filter data
 *   4 bytes    nHashFuncs          Number of hash functions
 *   4 bytes    nTweak              Random value to add to the hash seed
 *   1 byte     nFlags              Filter update flags
 * </pre>
 */
public class BloomFilter {

    /** Bloom filter flags */
    public static final int UPDATE_NONE = 0;            // Filter is not adjusted for matching outputs
    public static final int UPDATE_ALL = 1;             // Filter is adjusted for all matching outputs
    public static final int UPDATE_P2PUBKEY_ONLY = 2;   // Filter is adjusted only for pay-to-pubkey/multi-sig

    /** Maximum filter size */
    public static final int MAX_FILTER_SIZE = 36000;

    /** Maximum number of hash functions */
    public static final int MAX_HASH_FUNCS = 50;

    /** Filter data */
    private byte[] filter;

    /** Number of hash functions */
    private long nHashFuncs;

    /** Random tweak nonce */
    private long nTweak;

    /** Filter update flags */
    private int nFlags;

    /** Peer associated with this filter */
    private Peer peer;

    /**
     * Creates a Bloom filter from the serialized data
     *
     * @param       inStream                Serialized filter data
     * @throws      EOFException            End-of-data processing input stream
     * @throws      IOException             Unable to read input stream
     * @throws      VerificationException   Verification error
     */
    public BloomFilter(InputStream inStream) throws EOFException, IOException, VerificationException {
        byte[] bytes = new byte[4];
        //
        // Get the filter data
        //
        int byteCount = new VarInt(inStream).toInt();
        if (byteCount < 0 || byteCount > MAX_FILTER_SIZE)
            throw new VerificationException("Bloom filter size larger than 36000 bytes");
        filter = new byte[byteCount];
        int count = inStream.read(filter);
        if (count != byteCount)
            throw new EOFException("End-of-data while processing Bloom filter");
        //
        // Get the number of hash functions
        //
        count = inStream.read(bytes);
        if (count != 4)
            throw new EOFException("End-of-data while processing Bloom filter");
        nHashFuncs = Utils.readUint32LE(bytes, 0);
        //
        // Get the random tweak value
        //
        count = inStream.read(bytes);
        if (count != 4)
            throw new EOFException("End-of-data while processing Bloom filter");
        nTweak = Utils.readUint32LE(bytes, 0);
        //
        // Get the filter update flags
        //
        nFlags = inStream.read();
        if (nFlags<0)
            throw new EOFException("End-of-data while processing Bloom filter");
    }

    /**
     * Returns the filter flags
     *
     * @return      Filter flags
     */
    public int getFlags() {
        return nFlags;
    }

    /**
     * Sets the peer associated with this filter
     *
     * @param       peer            Peer
     */
    public void setPeer(Peer peer) {
        this.peer = peer;
    }

    /**
     * Returns the peer associated with this filter
     *
     * @return      Peer
     */
    public Peer getPeer() {
        return peer;
    }

    /**
     * Checks if the filter contains the specified object
     *
     * @param       object          Object to test
     * @return      TRUE if the filter contains the object
     */
    public boolean contains(byte[] object) {
        for (int i=0; i<nHashFuncs; i++) {
            if (!Utils.checkBitLE(filter, hash(i, object, 0, object.length)))
                return false;
        }
        return true;
    }

    /**
     * Checks if the filter contains the specified object
     *
     * @param       object          Object to test
     * @param       offset          Starting offset
     * @param       length          Length to check
     * @return      TRUE if the filter contains the object
     */
    public boolean contains(byte[] object, int offset, int length) {
        for (int i=0; i<nHashFuncs; i++) {
            if (!Utils.checkBitLE(filter, hash(i, object, offset, length)))
                return false;
        }
        return true;
    }

    /**
     * Inserts an object into the filter
     *
     * @param       object          Object to insert
     */
    public void insert(byte[] object) {
        for (int i=0; i<nHashFuncs; i++) {
            Utils.setBitLE(filter, hash(i, object, 0, object.length));
        }
    }

    /**
     * Check a transaction against the Bloom filter for a match
     *
     * @param       tx              Transaction to check
     * @return      TRUE if the transaction matches the filter
     * @throws      EOFException if an error occurs while processing a script
     */
    public boolean checkTransaction(Transaction tx) throws EOFException {
        boolean foundMatch = false;
        Sha256Hash txHash = tx.getHash();
        byte[] outpointData = new byte[36];
        //
        // Check the transaction hash
        //
        if (contains(txHash.getBytes()))
            return true;
        //
        // Check transaction outputs
        //
        // Test each script data element.  If a match is found, add
        // the serialized output point to the filter (if requested)
        // so the peer will be notified if the output is later spent.
        // We need to check all of the outputs since more than one transaction
        // in the block may be of interest and we would need to
        // update the filter for each one.
        //
        int index = 0;
        List<TransactionOutput> outputs = tx.getOutputs();
        for (TransactionOutput output : outputs) {
            //
            // Test the filter against each data element in the output script
            //
            byte[] scriptBytes = output.getScriptBytes();
            boolean isMatch = Script.checkFilter(this, scriptBytes);
            if (isMatch) {
                foundMatch = true;
                int type = Script.getPaymentType(scriptBytes);
                //
                // Update the filter with the outpoint if requested
                //
                if (nFlags==BloomFilter.UPDATE_ALL ||
                            (nFlags==BloomFilter.UPDATE_P2PUBKEY_ONLY &&
                                (type==Script.PAY_TO_PUBKEY || type==Script.PAY_TO_MULTISIG))) {
                    System.arraycopy(Utils.reverseBytes(txHash.getBytes()), 0, outpointData, 0, 32);
                    Utils.uint32ToByteArrayLE(index, outpointData, 32);
                    insert(outpointData);
                }
            }
            index++;
        }
        if (foundMatch)
            return true;
        //
        // Check transaction inputs
        //
        // Test each outpoint against the filter as well as each script data
        // element.
        //
        List<TransactionInput> inputs = tx.getInputs();
        for (TransactionInput input : inputs) {
            //
            // Test the filter against each data element in the input script
            // (don't test the coinbase transaction)
            //
            if (!tx.isCoinBase()) {
                byte[] scriptBytes = input.getScriptBytes();
                if (scriptBytes.length > 0) {
                    foundMatch = Script.checkFilter(this, scriptBytes);
                    if (foundMatch)
                        break;
                }
                //
                // Check the filter against the outpoint
                //
                if (contains(input.getOutPoint().bitcoinSerialize())) {
                    foundMatch = true;
                    break;
                }
            }
        }
        return foundMatch;
    }

    /**
     * Find matching transactions in the supplied block
     *
     * @param       block           Block containing the transactions
     * @return      List of matching transactions (List size will be 0 if no matches found)
     * @throws      EOFException
     */
    public List<Sha256Hash> findMatches(Block block) throws EOFException {
        List<Transaction> txList = block.getTransactions();
        List<Sha256Hash> matches = new ArrayList<>(txList.size());
        //
        // Check each transaction in the block
        //
        for (Transaction tx : txList) {
            if (checkTransaction(tx))
                matches.add(tx.getHash());
        }
        return matches;
    }

    /**
     * Rotate a 32-bit value left by the specified number of bits
     *
     * @param       x               The bit value
     * @param       count           The number of bits to rotate
     * @return      The new value
     */
    private int ROTL32(int x, int count) {
        return (x<<count) | (x>>>(32-count));
    }

    /**
     * Performs a MurmurHash3
     *
     * @param       hashNum         The hash number
     * @param       object          The byte array to hash
     * @param       offset          The starting offset
     * @param       length          Length to hash
     * @return      The hash of the object using the specified hash number
     */
    private int hash(int hashNum, byte[] object, int offset, int length) {
        int h1 = (int)(hashNum * 0xFBA4C795L + nTweak);
        final int c1 = 0xcc9e2d51;
        final int c2 = 0x1b873593;
        int numBlocks = (length / 4) * 4;
        //
        // Body
        //
        for(int i=0; i<numBlocks; i+=4) {
            int k1 = ((int)object[offset+i]&0xFF) | (((int)object[offset+i+1]&0xFF)<<8) |
                     (((int)object[offset+i+2]&0xFF)<<16) | (((int)object[offset+i+3]&0xFF)<<24);
            k1 *= c1;
            k1 = ROTL32(k1,15);
            k1 *= c2;
            h1 ^= k1;
            h1 = ROTL32(h1,13);
            h1 = h1*5+0xe6546b64;
        }
        int k1 = 0;
        switch(length & 3) {
            case 3:
                k1 ^= (object[offset+numBlocks + 2] & 0xff) << 16;
                // Fall through.
            case 2:
                k1 ^= (object[offset+numBlocks + 1] & 0xff) << 8;
                // Fall through.
            case 1:
                k1 ^= (object[offset+numBlocks] & 0xff);
                k1 *= c1; k1 = ROTL32(k1,15);
                k1 *= c2;
                h1 ^= k1;
                // Fall through.
            default:
                // Do nothing.
                break;
        }
        //
        // Finalization
        //
        h1 ^= length;
        h1 ^= h1 >>> 16;
        h1 *= 0x85ebca6b;
        h1 ^= h1 >>> 13;
        h1 *= 0xc2b2ae35;
        h1 ^= h1 >>> 16;
        return (int)((h1&0xFFFFFFFFL) % (filter.length * 8));
    }
}
