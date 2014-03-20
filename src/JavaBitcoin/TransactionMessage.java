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

import java.math.BigInteger;

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
        // Ignore the transaction if we have already seen it.  Otherwise, add it to
        // the recent transaction list
        //
        boolean duplicateTx = false;
        synchronized(Parameters.lock) {
            if (Parameters.recentTxMap.get(txHash) != null) {
                duplicateTx = true;
            } else {
                Parameters.recentTxList.add(txHash);
                Parameters.recentTxMap.put(txHash, txHash);
            }
        }
        if (duplicateTx)
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
                                            Parameters.REJECT_INVALID, txHash);
        //
        // Validate the transaction
        //
        if (!validateTx(tx))
            return;
        //
        // Broadcast the transaction to our peers
        //
        broadcastTx(tx);
        //
        // Process orphan transactions that were waiting on this transaction
        //
        List<StoredTransaction> orphanTxList;
        synchronized(Parameters.lock) {
            orphanTxList = Parameters.orphanTxMap.remove(txHash);
            if (orphanTxList != null) {
                for (StoredTransaction orphanStoredTx : orphanTxList)
                    Parameters.orphanTxList.remove(orphanStoredTx);
            }
        }
        if (orphanTxList != null) {
            for (StoredTransaction orphanStoredTx : orphanTxList) {
                Transaction orphanTx = orphanStoredTx.getTransaction();
                if (validateTx(orphanTx))
                    broadcastTx(orphanTx);
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
                Parameters.txPool.remove(0);
                Parameters.txMap.remove(poolTx.getHash());
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
            // Clean up the orphan transactions list
            while (Parameters.orphanTxList.size() > 1000) {
                StoredTransaction poolTx = Parameters.orphanTxList.remove(0);
                Parameters.orphanTxMap.remove(poolTx.getParent());
            }
        }
    }

    /**
     * Retry an orphan transaction
     *
     * @param       tx                      Transaction
     */
    public static void retryOrphanTransaction(Transaction tx) {
        try {
            if (validateTx(tx))
                broadcastTx(tx);
        } catch (EOFException | VerificationException exc) {
           // Ignore the transaction since it is no longer valid
        }
    }

    /**
     * Validates the transaction
     *
     * @param       tx                      Transaction
     * @return                              TRUE if the transaction is valid
     * @throws      EOFException            End-of-data processing script
     * @throws      VerificationException   Transaction validation failed
     */
    private static boolean validateTx(Transaction tx) throws EOFException, VerificationException {
        Sha256Hash txHash = tx.getHash();
        BigInteger totalInput = BigInteger.ZERO;
        BigInteger totalOutput = BigInteger.ZERO;
        //
        // Validate the transaction outputs
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
            // Add the output value to the total output value for the transaction
            totalOutput = totalOutput.add(output.getValue());
        }
        //
        // Validate the transaction inputs
        //
        List<OutPoint> spentOutputs = new LinkedList<>();
        List<TransactionInput> inputs = tx.getInputs();
        boolean orphanTx = false;
        boolean duplicateTx = false;
        Sha256Hash orphanHash = null;
        for (TransactionInput input : inputs) {
            // Script size must not exceed 500 bytes
            if (input.getScriptBytes().length > 500)
                throw new VerificationException("Input script size greater than 500 bytes",
                                                Parameters.REJECT_NONSTANDARD, txHash);
            // Connected output must not be spent
            OutPoint outPoint = input.getOutPoint();
            StoredOutput output = null;
            Sha256Hash spendHash;
            boolean outputSpent = false;
            synchronized(Parameters.lock) {
                spendHash = Parameters.spentOutputsMap.get(outPoint);
            }
            if (spendHash == null) {
                // Connected output is not in the recently spent list, check the memory pool
                StoredTransaction outTx;
                synchronized(Parameters.lock) {
                    outTx = Parameters.txMap.get(outPoint.getHash());
                }
                if (outTx != null) {
                    // Transaction is in the memory pool, get the connected output
                    List<TransactionOutput> txOutputs = outTx.getTransaction().getOutputs();
                    for (TransactionOutput txOutput : txOutputs) {
                        if (txOutput.getIndex() == outPoint.getIndex()) {
                            totalInput = totalInput.add(txOutput.getValue());
                            output = new StoredOutput(txOutput.getIndex(), txOutput.getValue(),
                                                      txOutput.getScriptBytes());
                            break;
                        }
                    }
                    if (output == null)
                        throw new VerificationException(String.format(
                                "Transaction references non-existent output\n  %s", txHash.toString()),
                                Parameters.REJECT_INVALID, txHash);
                } else {
                    // Transaction is not in the memory pool, check the database
                    try {
                        output = Parameters.blockStore.getTxOutput(outPoint);
                        if (output == null) {
                            orphanTx = true;
                            orphanHash = outPoint.getHash();
                        } else if (output.isSpent()) {
                            outputSpent = true;
                        } else {
                            totalInput = totalInput.add(output.getValue());
                        }
                    } catch (BlockStoreException exc) {
                        orphanTx = true;
                        orphanHash = outPoint.getHash();
                    }
                }
            } else if (!spendHash.equals(txHash)) {
                outputSpent = true;
            } else {
                duplicateTx = true;
            }
            // Stop now if we have a problem
            if (duplicateTx || orphanTx)
                break;
            // Error if the output has been spent
            if (outputSpent)
                throw new VerificationException("Input already spent", Parameters.REJECT_DUPLICATE, txHash);
            // Check for canonical signatures and public keys
            int paymentType = Script.getPaymentType(output.getScriptBytes());
            List<byte[]> dataList = Script.getData(input.getScriptBytes());
            int canonicalType = 0;
            switch (paymentType) {
                case Script.PAY_TO_PUBKEY:
                    // First data element is signature
                    if (dataList.isEmpty() || !ECKey.isSignatureCanonical(dataList.get(0)))
                        canonicalType = 1;
                    break;
                case Script.PAY_TO_PUBKEY_HASH:
                    // First data element is signature, second data element is public key
                    if (dataList.isEmpty() || !ECKey.isSignatureCanonical(dataList.get(0)))
                        canonicalType = 1;
                    else if (dataList.size() < 2 || !ECKey.isPubKeyCanonical(dataList.get(1)))
                        canonicalType = 2;
                    break;
                case Script.PAY_TO_MULTISIG:
                    // All data elements are public keys
                    for (byte[] sigBytes : dataList) {
                        if (!ECKey.isSignatureCanonical(sigBytes)) {
                            canonicalType = 1;
                            break;
                        }
                    }
            }
            if (canonicalType == 1)
                throw new VerificationException(String.format("Non-canonical signature",
                                                txHash.toString()), Parameters.REJECT_NONSTANDARD, txHash);
            if (canonicalType == 2)
                throw new VerificationException(String.format("Non-canonical public key",
                                                txHash.toString()), Parameters.REJECT_NONSTANDARD, txHash);
            // Add the output to the spent outputs list
            spentOutputs.add(outPoint);
        }
        //
        // Ignore a duplicate transaction (race condition among message handler threads)
        //
        if (duplicateTx)
            return false;
        //
        // Save an orphan transaction for later
        //
        if (orphanTx) {
            StoredTransaction storedTx = new StoredTransaction(tx);
            storedTx.setParent(orphanHash);
            synchronized(Parameters.lock) {
                Parameters.orphanTxList.add(storedTx);
                List<StoredTransaction> orphanList = Parameters.orphanTxMap.get(orphanHash);
                if (orphanList == null) {
                    orphanList = new LinkedList<>();
                    orphanList.add(storedTx);
                    Parameters.orphanTxMap.put(orphanHash, orphanList);
                } else {
                    orphanList.add(storedTx);
                }
            }
            return false;
        }
        //
        // Check for insufficient transaction fee
        //
        BigInteger totalFee = totalInput.subtract(totalOutput);
        if (totalFee.signum() < 0)
            throw new VerificationException("Transaction output value exceeds transaction input value",
                                            Parameters.REJECT_INVALID, txHash);
        int txLength = tx.getBytes().length;
        int feeMultiplier = txLength/1000;
        if (txLength > Parameters.MAX_FREE_TX_SIZE) {
            BigInteger minFee = Parameters.MIN_TX_RELAY_FEE.multiply(BigInteger.valueOf(feeMultiplier+1));
            if (totalFee.compareTo(minFee) < 0)
                throw new VerificationException("Insufficient transaction fee",
                                                Parameters.REJECT_INSUFFICIENT_FEE, txHash);
        }
        //
        // Store the transaction in the memory pool (maximum size we will store is 50KB)
        //
        if (txLength <= 50*1024) {
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
                }
            }
        }
        return true;
    }

    /**
     * Broadcasts the transaction
     *
     * @param       tx                  Transaction
     * @throws      EOFException        End-of-data processing script
     */
    private static void broadcastTx(Transaction tx) throws EOFException {
        Sha256Hash txHash = tx.getHash();
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
        List<BloomFilter> filters;
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
}
