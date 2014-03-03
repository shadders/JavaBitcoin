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
 * <p>The 'filteradd' message is sent to add an additional element to an existing Bloom
 * filter.</p>
 *
 * <p>FilterAdd Message</p>
 * <pre>
 *   Size       Field           Description
 *   ====       =====           ===========
 *   VarInt     Count           Number of bytes in the filter element (maximum of 520)
 *   Variable   Element         Filter element
 * </pre>
 */
public class FilterAddMessage {

    /**
     * Processes a 'filteradd' message
     *
     * @param       msg             Message
     * @param       inStream        Message data stream
     * @throws      EOFException
     * @throws      IOException
     * @throws      VerificationException
     */
    public static void processFilterAddMessage(Message msg, ByteArrayInputStream inStream)
                                    throws EOFException, IOException, VerificationException {
        //
        // Get the size of the filter element
        //
        int varCount = new VarInt(inStream).toInt();
        if (varCount < 0 || varCount > 520)
            throw new VerificationException("'filteradd' filter length greater than 520 bytes");
        byte[] filterData = new byte[varCount];
        int count = inStream.read(filterData);
        if (count < varCount)
            throw new EOFException("Premature end-of-data while processing 'filteradd' message");
        //
        // Add the element to the existing filter
        //
        Peer peer = msg.getPeer();
        BloomFilter filter = peer.getBloomFilter();
        if (filter != null)
            filter.insert(filterData);
    }
}
