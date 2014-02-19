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
import java.util.List;

/**
 * <p>The 'getheaders' request returns a list of block headers.  This is similar to
 * the 'getblocks' request and is used by SPV clients who don't need the entire block.
 * The response is a 'headers' message containing up to 2000 block headers.</p>
 *
 * <p>GetHeaders Message</p>
 * <pre>
 *   Size       Field               Description
 *   ====       =====               ===========
 *   4 bytes    Version             Negotiated protocol version
 *   VarInt     Count               Number of locator hash entries
 *   Variable   Entries             Locator hash entries
 *  32 bytes    Stop                Hash of the last desired block or zero to get as many as possible
 * </pre>
 */
public class GetHeadersMessage {

    /**
     * Process the 'getheaders' message and return a 'headers' response
     *
     * @param       msg             Message
     * @param       inStream        Message data stream
     * @throws      EOFException    Message stream is too short
     * @throws      IOException     Unable to read the message stream
     * @throws      VerificationException  Message verification failed
     */
    public static void processGetHeadersMessage(Message msg, ByteArrayInputStream inStream)
                                    throws EOFException, IOException, VerificationException {
        Peer peer = msg.getPeer();
        //
        // Get the protocol version
        //
        byte[] bytes = new byte[32];
        int count = inStream.read(bytes, 0, 4);
        if (count < 4)
            throw new EOFException("End-of-data processing 'getheaders' message");
        int version = (int)Utils.readUint32LE(bytes, 0);
        if (version < Parameters.MIN_PROTOCOL_VERSION)
            throw new VerificationException(String.format("Protocol version %d is not supported", version));
        //
        // Get the number of locator entries
        //
        int varCount = new VarInt(inStream).toInt();
        if (varCount < 0 || varCount > 500)
            throw new VerificationException(String.format("'getheaders' message contains more than 500 locators"));
        //
        // Check each locator until we find one that is on the main chain
        //
        try {
            boolean foundJunction = false;
            Sha256Hash blockHash = null;
            inStream.mark(0);
            for (int i=0; i<varCount; i++) {
                count = inStream.read(bytes, 0, 32);
                if (count < 32)
                    throw new EOFException("End-of-data processing 'getheaders' message");
                blockHash = new Sha256Hash(Utils.reverseBytes(bytes));
                if (Parameters.blockStore.isOnChain(blockHash)) {
                    foundJunction = true;
                    break;
                }
            }
            //
            // We go back to the genesis block if none of the supplied locators are on the main chain
            //
            if (!foundJunction)
                blockHash = new Sha256Hash(Parameters.GENESIS_BLOCK_HASH);
            //
            // Get the stop block
            //
            inStream.reset();
            inStream.skip(varCount*32);
            count = inStream.read(bytes, 0, 32);
            if (count < 32)
                throw new EOFException("End-of-data processing 'getheaders' message");
            Sha256Hash stopHash = new Sha256Hash(bytes);
            //
            // Get the chain list
            //
            List<byte[]> chainList = Parameters.blockStore.getHeaderList(blockHash, stopHash);
            //
            // Build the 'headers' response
            //
            Message hdrMsg = HeadersMessage.buildHeadersMessage(peer, chainList);
            msg.setBuffer(hdrMsg.getBuffer());
            msg.setCommand(MessageHeader.HEADERS_CMD);
        } catch (BlockStoreException exc) {
            //
            // Can't access the database, so just ignore the 'getheaders' request
            //
        }
    }
}
