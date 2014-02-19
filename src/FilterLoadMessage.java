/**
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

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;

/**
 * <p>The 'filterload' message supplies a Bloom filter to select transactions
 * of interest to the requester.  The requester will be notified when transactions
 * are received that match the supplied filter.  The requester can then respond
 * with a 'getdata' message to request Merkle blocks for those transactions.</p>
 *
 * <p>FilterLoad Message</p>
 * <pre>
 *   Size       Field           Description
 *   ====       =====           ===========
 *   VarInt     byteCount       Number of bytes in the filter (maximum of 36,000)
 *   Variable   filter          Bloom filter
 *   4 bytes    nHashFuncs      Number of hash functions
 *   4 bytes    nTweak          Random value to add to seed value
 *   1 byte     nFlags          Matching flags
 * </pre>
 */
public class FilterLoadMessage {

    /**
     * Creates the Bloom filter
     *
     * @param       msg                     Message
     * @param       inStream                Input message stream
     * @throws      EOFException            End-of-data processing input stream
     * @throws      IOException             Unable to read input stream
     * @throws      VerificationException   Verification error
     */
    public static void processFilterLoadMessage(Message msg, ByteArrayInputStream inStream)
                                    throws EOFException, IOException, VerificationException {
        Peer peer = msg.getPeer();
        BloomFilter filter = new BloomFilter(inStream);
        BloomFilter oldFilter = peer.getBloomFilter();
        filter.setPeer(peer);
        peer.setBloomFilter(filter);
        //
        // Add the filter to the list of Bloom filters
        //
        synchronized(Parameters.lock) {
            if (oldFilter != null)
                Parameters.bloomFilters.remove(filter);
            Parameters.bloomFilters.add(filter);
        }
    }
}
