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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;

/**
 * <p>The 'headers' message is returned in response to a 'getheaders' message.
 * Note that the returned header includes the block header (80 bytes) plus
 * the transaction count (although the count is set to zero)</p>
 *
 * <p>Headers Message</p>
 * <pre>
 *   Size       Field               Description
 *   ====       =====               ===========
 *   VarInt     Count               Number of headers
 *   Variable   Entries             Header entries
 * </pre>
 */
public class HeadersMessage {

    /**
     * Build the 'headers' message
     *
     * @param       peer            Destination peer
     * @param       chainList       List of chain block headers
     * @return                      Headers message
     * @throws      IOException     Unable to write to the output stream
     */
    public static Message buildHeadersMessage(Peer peer, List<byte[]> chainList) throws IOException {
        //
        // Write the header count
        //
        int hdrCount = chainList.size();
        byte[] varCount = VarInt.encode(hdrCount);
        ByteArrayOutputStream outStream = new ByteArrayOutputStream(hdrCount*81+2);
        outStream.write(varCount);
        //
        // Write the headers (set the transaction count to 0)
        //
        for (byte[] hdrData : chainList) {
            outStream.write(hdrData, 0, Block.HEADER_SIZE);
            outStream.write(0);
        }
        //
        // Build the message
        //
        byte[] msgData = outStream.toByteArray();
        ByteBuffer buffer = MessageHeader.buildMessage("headers", msgData);
        return new Message(buffer, peer, MessageHeader.HEADERS_CMD);
    }
}
