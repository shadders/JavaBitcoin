/**
 * Copyright 2013-2014 Ronald W Hoffman
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
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 * <p>The 'getdata' message is used to request one or more blocks and transactions.
 * Blocks are returned as 'block' messages and transactions are returned as 'tx'
 * messages.  Any entries that are not found are returned as a 'notfound' response.</p>
 *
 * <p>GetData Message:</p>
 * <pre>
 *   Size       Field               Definition
 *   ====       =====               ==========
 *   VarInt     Count               Number of inventory vectors
 *   Variable   InvVectors          One or more inventory vectors
 * </pre>
 *
 * <p>Inventory Vector:</p>
 * <pre>
 *   Size       Field               Description
 *   ====       =====               ===========
 *   4 bytes    Type                0=Error, 1=Transaction, 2=Block, 3=Filtered block
 *  32 bytes    Hash                Object hash
 * </pre>
 */
public class GetDataMessage {

    /**
     * Create a 'getdata' message
     *
     * @param       peer            Peer node
     * @param       type            Request type (INV_TX or INV_BLOCK)
     * @param       hashList        Hash list
     * @return      Message
     */
    public static Message buildGetDataMessage(Peer peer, int type, List<Sha256Hash> hashList) {
        int varCount = hashList.size();
        byte[] varBytes = VarInt.encode(varCount);
        byte[] msgData = new byte[varBytes.length+varCount*36];
        //
        // Build the message payload
        //
        System.arraycopy(varBytes, 0, msgData, 0, varBytes.length);
        int offset = varBytes.length;
        for (int i=0; i<varCount; i++) {
            Sha256Hash hash = hashList.get(i);
            Utils.uint32ToByteArrayLE(type, msgData, offset);
            System.arraycopy(Utils.reverseBytes(hash.getBytes()), 0, msgData, offset+4, 32);
            offset+=36;
        }
        //
        // Build the message
        //
        ByteBuffer buffer = MessageHeader.buildMessage("getdata", msgData);
        return new Message(buffer, peer,
                (type==Parameters.INV_BLOCK?MessageHeader.INVBLOCK_CMD:MessageHeader.INVTX_CMD));
    }

    /**
     * Process a 'getdata' message
     *
     * @param       msg                     Message
     * @param       inStream                Message data stream
     * @throws      EOFException            End-of-data while processing message data
     * @throws      IOException             Unable to read message data
     * @throws      VerificationException   Data verification failed
     */
    public static void processGetDataMessage(Message msg, ByteArrayInputStream inStream)
                                             throws EOFException, IOException, VerificationException {
        Peer peer = msg.getPeer();
        int blocksSent = 0;
        int txSent = 0;
        //
        // Get the number of inventory entries
        //
        int varCount = new VarInt(inStream).toInt();
        if (varCount < 0 || varCount > 1000)
            throw new VerificationException("More than 1000 inventory entries in 'getdata' message");
        //
        // Process each request
        //
        // If this is a restarted request, we need to skip over the requests that have already
        // been processed as indicated by the restart index contained in the message.
        //
        List<byte[]> notFound = new LinkedList<>();
        byte[] invBytes = new byte[36];
        int restart = msg.getRestartIndex();
        msg.setRestartIndex(0);
        if (restart != 0)
            inStream.skip(restart*36);
        for (int i=restart; i<varCount; i++) {
            //
            // Defer the request if we have sent 50 blocks in the current batch
            //
            if (blocksSent == 50) {
                msg.setRestartIndex(i);
                break;
            }
            int count = inStream.read(invBytes);
            if (count < 36)
                throw new EOFException("End-of-data while processing 'getdata' message");
            int invType = (int)Utils.readUint32LE(invBytes, 0);
            Sha256Hash hash = new Sha256Hash(Utils.reverseBytes(invBytes, 4, 32));
            if (invType == Parameters.INV_TX) {
                //
                // Send a transaction from the transaction memory pool.  We won't send more
                // than 500 transactions for a single 'getdata' request
                //
                if (txSent < 500) {
                    StoredTransaction tx;
                    synchronized(Parameters.lock) {
                        tx = Parameters.txMap.get(hash);
                    }
                    if (tx != null) {
                        txSent++;
                        ByteBuffer buffer = MessageHeader.buildMessage("tx", tx.getBytes());
                        Message txMsg = new Message(buffer, peer, MessageHeader.TX_CMD);
                        Parameters.networkListener.sendMessage(txMsg);
                        synchronized(Parameters.lock) {
                            Parameters.txSent++;
                        }
                    } else {
                        notFound.add(Arrays.copyOf(invBytes, 36));
                    }
                } else {
                    notFound.add(Arrays.copyOf(invBytes, 36));
                }
            } else if (invType == Parameters.INV_BLOCK) {
                //
                // Send a block from the database or an archive file.  We will send the
                // blocks in increments of 10 to avoid running out of storage.  If more
                // then 10 blocks are requested, the request will be deferred until 10
                // have been sent, then the request will resume with the next 10 blocks.
                //
                try {
                    Block block = Parameters.blockStore.getBlock(hash);
                    if (block != null) {
                        blocksSent++;
                        ByteBuffer buffer = MessageHeader.buildMessage("block", block.bitcoinSerialize());
                        Message blockMsg = new Message(buffer, peer, MessageHeader.BLOCK_CMD);
                        Parameters.networkListener.sendMessage(blockMsg);
                        synchronized(Parameters.lock) {
                            Parameters.blocksSent++;
                        }
                    } else {
                        notFound.add(Arrays.copyOf(invBytes, 36));
                    }
                } catch (BlockStoreException exc) {
                    notFound.add(Arrays.copyOf(invBytes, 36));
                }
            } else if (invType == Parameters.INV_FILTERED_BLOCK) {
                //
                // Send a filtered block if the peer has loaded a Bloom filter
                //
                BloomFilter filter = peer.getBloomFilter();
                if (filter == null)
                    continue;
                //
                // Get the block from the database and return not found if we don't have it
                //
                Block block;
                try {
                    block = Parameters.blockStore.getBlock(hash);
                } catch (BlockStoreException exc) {
                    block = null;
                }
                if (block == null) {
                    //
                    // Change the inventory type to INV_BLOCK so the client doesn't choke
                    // on the 'notfound' message
                    //
                    Utils.uint32ToByteArrayLE(Parameters.INV_BLOCK, invBytes, 0);
                    notFound.add(Arrays.copyOf(invBytes, 36));
                    continue;
                }
                //
                // Find any matching transactions in the block
                //
                List<Sha256Hash> matches = filter.findMatches(block);
                //
                // Send a 'merkleblock' message followed by 'tx' messages for the matches
                //
                sendMatchedTransactions(peer, block, matches);
            } else {
                //
                // Unrecognized message type
                //
                notFound.add(Arrays.copyOf(invBytes, 36));
            }
        }
        //
        // Create a 'notfound' response if we didn't find all of the requested items
        //
        if (!notFound.isEmpty()) {
            varCount = notFound.size();
            byte[] varBytes = VarInt.encode(varCount);
            byte[] msgData = new byte[varCount*36+varBytes.length];
            System.arraycopy(varBytes, 0, msgData, 0, varBytes.length);
            int offset = varBytes.length;
            for (byte[] invItem : notFound) {
                System.arraycopy(invItem, 0, msgData, offset, 36);
                offset += 36;
            }
            ByteBuffer buffer = MessageHeader.buildMessage("notfound", msgData);
            msg.setBuffer(buffer);
            msg.setCommand(MessageHeader.NOTFOUND_CMD);
        }
    }

    /**
     * Sends a 'merkleblock' message followed by 'tx' messages for the matched transaction
     *
     * @param       peer            Destination peer
     * @param       block           Block containing the transactions
     * @param       matches         List of matching transactions
     * @throws      IOException     Error creating serialized data stream
     */
    public static void sendMatchedTransactions(Peer peer, Block block, List<Sha256Hash> matches)
                                    throws IOException {
        //
        // Build the index list for the matching transactions
        //
        List<Integer> txIndexes;
        List<Transaction> txList = null;
        if (matches.isEmpty()) {
            txIndexes = new ArrayList<>();
        } else {
            txIndexes = new ArrayList<>(matches.size());
            txList = block.getTransactions();
            int index = 0;
            for (Transaction tx : txList) {
                if (matches.contains(tx.getHash()))
                    txIndexes.add(Integer.valueOf(index));
                index++;
            }
        }
        //
        // Build and send the 'merkleblock' message
        //
        Message blockMsg = MerkleBlockMessage.buildMerkleBlockMessage(peer, block, txIndexes);
        Parameters.networkListener.sendMessage(blockMsg);
        synchronized(Parameters.lock) {
            Parameters.filteredBlocksSent++;
        }
        //
        // Send 'tx' messages for each matching transaction
        //
        for (Integer txIndex : txIndexes) {
            Transaction tx = txList.get(txIndex.intValue());
            byte[] txData = tx.getBytes();
            ByteBuffer buffer = MessageHeader.buildMessage("tx", txData);
            Message txMsg = new Message(buffer, peer, MessageHeader.TX_CMD);
            Parameters.networkListener.sendMessage(txMsg);
            synchronized(Parameters.lock) {
                Parameters.txSent++;
            }
        }
    }
}
