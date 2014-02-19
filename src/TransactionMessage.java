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
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

/**
 * <p>The 'tx' message contains a transaction which is not yet in a block.  The transaction
 * will be held in the memory pool for a period of time to allow other peers to request
 * the transaction.</p>
 *
 * <p>Transaction Message</p>
 * <pre>
 *   Size           Field               Description
 *   ====           =====               ===========
 *   4 bytes        Version             Transaction version
 *   VarInt         InputCount          Number of inputs
 *   Variable       InputList           Inputs
 *   VarInt         OutputCount         Number of outputs
 *   Variable       OutputList          Outputs
 *   4 bytes        LockTime            Transaction lock time
 * </pre>
 */
public class TransactionMessage {

    /**
     * Processes a 'tx' message
     *
     * @param       msg                     Message
     * @param       inStream                Message data stream
     * @throws      EOFException            Serialized data is too short
     * @throws      IOException             Error reading input stream
     * @throws      VerificationException   Transaction verification failed
     */
    public static void processTransactionMessage(Message msg, ByteArrayInputStream inStream)
                                    throws EOFException, IOException, VerificationException {
        //
        // Get the transaction
        //
        int length = inStream.available();
        byte[] msgData = new byte[length];
        inStream.read(msgData);
        SerializedInputStream txStream = new SerializedInputStream(msgData, 0, length);
        Transaction tx = new Transaction(txStream);
        Sha256Hash txHash = tx.getHash();
        //
        // Remove the request from the processedRequests list
        //
        synchronized(Parameters.lock) {
            Iterator<PeerRequest> it = Parameters.processedRequests.iterator();
            while (it.hasNext()) {
                PeerRequest request = it.next();
                if (request.getType()==Parameters.INV_TX && request.getHash().equals(txHash)) {
                    it.remove();
                    break;
                }
            }
        }
        //
        // Ignore the transaction if we have already seen it
        //
        synchronized(Parameters.lock) {
            if (Parameters.recentTxMap.get(txHash) != null ||
                                Parameters.txMap.get(txHash) != null)
                txHash = null;
        }
        if (txHash == null)
            return;
        //
        // Verify the transaction
        //
        tx.verify(true);
       //
        // Coinbase transaction cannot be relayed
        //
        if (tx.isCoinBase())
            throw new VerificationException("Coinbase transaction cannot be relayed",
                                            Parameters.REJECT_INVALID, tx.getHash());
        //
        // Check for non-standard transactions that won't be relayed
        //
        List<TransactionOutput> outputs = tx.getOutputs();
        for (TransactionOutput output : outputs) {
            // Dust transactions are not relayed
            if (output.getValue().compareTo(Parameters.DUST_TRANSACTION) < 0)
                throw new VerificationException("Dust transactions are not relayed",
                                                Parameters.REJECT_DUST, tx.getHash());
            // Non-standard payment types are not relayed
            int paymentType = Script.getPaymentType(output.getScriptBytes());
            if (paymentType != Script.PAY_TO_PUBKEY_HASH &&
                                    paymentType != Script.PAY_TO_PUBKEY &&
                                    paymentType != Script.PAY_TO_SCRIPT_HASH &&
                                    paymentType != Script.PAY_TO_MULTISIG &&
                                    paymentType != Script.PAY_TO_NOBODY) {
                Main.dumpData("Failing Script", output.getScriptBytes());
                throw new VerificationException("Non-standard payment types are not relayed",
                                                Parameters.REJECT_NONSTANDARD, txHash);
            }
        }
        List<OutPoint> spentOutputs = new LinkedList<>();
        List<TransactionInput> inputs = tx.getInputs();
        for (TransactionInput input : inputs) {
            // Script size must be less than 500 bytes
            if (input.getScriptBytes().length > 500)
                throw new VerificationException("Input script size greater than 500 bytes",
                                                Parameters.REJECT_NONSTANDARD, txHash);
            // Connected output must not be spent
            OutPoint outPoint = input.getOutPoint();
            Sha256Hash spendHash;
            synchronized(Parameters.lock) {
                spendHash = Parameters.spentOutputsMap.get(outPoint);
            }
            if (spendHash == null)
                spentOutputs.add(outPoint);
            else if (!spendHash.equals(txHash))
                throw new VerificationException(String.format("Input already spent by %s", spendHash.toString()),
                                                Parameters.REJECT_DUPLICATE, txHash);
        }
        //
        // Store the transaction in the memory pool (maximum size we will store is 100KB)
        //
        if (length <= 100*1024) {
            StoredTransaction storedTx = new StoredTransaction(tx);
            synchronized(Parameters.lock) {
                if (Parameters.txMap.get(txHash) == null) {
                    Parameters.txPool.add(storedTx);
                    Parameters.txMap.put(txHash, storedTx);
                    Parameters.txReceived++;
                    for (OutPoint outPoint : spentOutputs) {
                        Parameters.spentOutputsList.add(outPoint);
                        Parameters.spentOutputsMap.put(outPoint, txHash);
                    }
                } else {
                    txHash = null;
                }
            }
        } else {
            txHash = null;
        }
        //
        // Notify our peers that we have a new transaction
        //
        if (txHash != null) {
            //
            // Send an 'inv' message to the broadcast peers
            //
            List<Sha256Hash> txList = new ArrayList<>(1);
            txList.add(txHash);
            Message invMsg = InventoryMessage.buildInventoryMessage(null, Parameters.INV_TX, txList);
            Parameters.networkListener.broadcastMessage(invMsg);
            //
            // Copy the current list of Bloom filters
            //
            List<BloomFilter> filters = null;
            synchronized(Parameters.lock) {
                filters = new ArrayList<>(Parameters.bloomFilters.size());
                filters.addAll(Parameters.bloomFilters);
            }
            //
            // Check each filter for a match
            //
            for (BloomFilter filter : filters) {
                Peer peer = filter.getPeer();
                //
                // Remove the filter if the peer is no longer connected
                //
                if (!peer.isConnected()) {
                    synchronized(Parameters.lock) {
                        Parameters.bloomFilters.remove(filter);
                    }
                    continue;
                }
                //
                // Check the transaction against the filter and send an 'inv' message if it is a match
                //
                if (filter.checkTransaction(tx)) {
                    invMsg = InventoryMessage.buildInventoryMessage(peer, Parameters.INV_TX, txList);
                    Parameters.networkListener.sendMessage(invMsg);
                }
            }
        }
        //
        // Purge transactions from the memory pool after 15 minutes.  We will limit the
        // transaction lists to 5000 entries each.
        //
        synchronized(Parameters.lock) {
            long oldestTime = System.currentTimeMillis()/1000 - (15*60);
            // Clean up the transaction pool
            while (!Parameters.txPool.isEmpty()) {
                StoredTransaction poolTx = Parameters.txPool.get(0);
                if (poolTx.getTimeStamp()>=oldestTime && Parameters.txPool.size()<=5000)
                    break;
                Sha256Hash poolHash = poolTx.getHash();
                Parameters.txPool.remove(0);
                Parameters.txMap.remove(poolHash);
                if (Parameters.recentTxMap.get(poolHash) == null) {
                    Parameters.recentTxList.add(poolHash);
                    Parameters.recentTxMap.put(poolHash, poolHash);
                }
            }
            // Clean up the recent transaction list
            while (Parameters.recentTxList.size() > 5000) {
                Sha256Hash poolHash = Parameters.recentTxList.remove(0);
                Parameters.recentTxMap.remove(poolHash);
            }
            // Clean up the spent outputs list
            while (Parameters.spentOutputsList.size() > 5000) {
                OutPoint outPoint = Parameters.spentOutputsList.remove(0);
                Parameters.spentOutputsMap.remove(outPoint);
            }
        }
    }
}
