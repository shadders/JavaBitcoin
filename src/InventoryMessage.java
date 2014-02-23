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
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * <p>The 'inv' message is sent by a remote peer to advertise blocks and transactions
 * that are available.  This message can be unsolicited or in response to a 'getblocks'
 * request.</p>
 *
 * <p>We will add items that we don't have to the 'pendingRequests' queue.  This will cause
 * the network listener to send 'getdata' requests to get the missing items.</p>
 *
 * <p>Inventory Message:</p>
 * <pre>
 *   Size       Field               Description
 *   ====       =====               ===========
 *   VarInt     Count               Number of inventory vectors
 *   Variable   InvVector           One or more inventory vectors
 * </pre>
 *
 * <p>Inventory Vector:</p>
 * <pre>
 *   Size       Field               Description
 *   ====       =====               ===========
 *   4 bytes    Type                0=Error, 1=Transaction, 2=Block
 *  32 bytes    Hash                Object hash
 * </pre>
 */
public class InventoryMessage {

    /** Garbage transactions that keep getting re-broadcast */
    private static final List<Sha256Hash> badTransactions = new ArrayList<>(10);
    static {
        badTransactions.add(new Sha256Hash("d21633ba23f70118185227be58a63527675641ad37967e2aa461559f577aec43"));
    }

    /**
     * Build an 'inv' message
     *
     * @param       peer            Destination peer
     * @param       type            Inventory type (INV_TX or INV_BLOCK)
     * @param       hashList        Inventory hash list
     * @return                      Message to send to the peer
     */
    public static Message buildInventoryMessage(Peer peer, int type, List<Sha256Hash> hashList) {
        byte[] varCount = VarInt.encode(hashList.size());
        byte[] msgData = new byte[hashList.size()*36+varCount.length];
        //
        // Build the message payload
        //
        System.arraycopy(varCount, 0, msgData, 0, varCount.length);
        int offset = varCount.length;
        for (Sha256Hash hash : hashList) {
            Utils.uint32ToByteArrayLE(type, msgData, offset);
            System.arraycopy(Utils.reverseBytes(hash.getBytes()), 0, msgData, offset+4, 32);
            offset += 36;
        }
        //
        // Build the message
        //
        ByteBuffer buffer = MessageHeader.buildMessage("inv", msgData);
        return new Message(buffer, peer,
                (type==Parameters.INV_BLOCK?MessageHeader.INVBLOCK_CMD:MessageHeader.INVTX_CMD));
    }

    /**
     * Process an 'inv' message.
     *
     * @param       msg                     Message
     * @param       inStream                Message data stream
     * @throws      EOFException            End-of-data while processing data stream
     * @throws      IOException             Unable to read data stream
     * @throws      VerificationException   Verification error
     */
    public static void processInventoryMessage(Message msg, ByteArrayInputStream inStream)
                                    throws EOFException, IOException, VerificationException {
        byte[] bytes = new byte[36];
        Peer peer = msg.getPeer();
        //
        // Get the number of inventory vectors (maximum of 1000 entries)
        //
        int invCount = new VarInt(inStream).toInt();
        if (invCount < 0 || invCount > 1000)
            throw new VerificationException("More than 1000 entries in 'inv' message", Parameters.REJECT_INVALID);
        //
        // Process the inventory vectors
        //
        for (int i=0; i<invCount; i++) {
            int count = inStream.read(bytes);
            if (count < 36)
                throw new EOFException("End-of-data processing 'inv' message");
            int type = (int)Utils.readUint32LE(bytes, 0);
            Sha256Hash hash = new Sha256Hash(Utils.reverseBytes(bytes, 4, 32));
            PeerRequest request = new PeerRequest(hash, type, peer);
            if (type == Parameters.INV_TX) {
                //
                // Ignore large transaction broadcasts (bad clients are sending large
                // inventory lists with unknown transactions over and over again)
                //
                if (invCount > 100)
                    throw new VerificationException("More than 100 tx entries in 'inv' message",
                                                    Parameters.REJECT_INVALID);
                //
                // Ignore known bad transactions
                //
                if (badTransactions.contains(hash))
                    continue;
                //
                // Skip the transaction if we have already seen it
                //
                boolean newTx = false;
                synchronized(Parameters.lock) {
                    if (Parameters.recentTxMap.get(hash) == null)
                        newTx = true;
                }
                if (!newTx)
                    continue;
                //
                // Request the transaction if it is not in the transaction memory pool
                // and has not been requested.  We add the request at the front of the
                // queue so it does not get stuck behind pending block requests.
                //
                try {
                    if (Parameters.blockStore.isNewTransaction(hash)) {
                        synchronized(Parameters.lock) {
                            if (Parameters.recentTxMap.get(hash) == null &&
                                                !Parameters.pendingRequests.contains(request) &&
                                                !Parameters.processedRequests.contains(request)) {
                                Parameters.pendingRequests.add(0, request);
                            }
                        }
                    }
                } catch (BlockStoreException exc) {
                    // Unable to check database - wait for another inventory broadcast
                }
            } else if (type == Parameters.INV_BLOCK) {
                //
                // Request the block if it is not in the database and has not been requested.
                // Block requests are added to the end of the queue so that we don't hold
                // up transaction requests while we update the block chain.
                //
                try {
                    if (Parameters.blockStore.isNewBlock(hash)) {
                        synchronized(Parameters.lock) {
                            if (!Parameters.pendingRequests.contains(request) &&
                                            !Parameters.processedRequests.contains(request)) {
                                Parameters.pendingRequests.add(request);
                            }
                        }
                    }
                } catch (BlockStoreException exc) {
                    // Unable to check database - wait for another inventory broadcast
                }
            }
        }
    }
}
