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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;

import java.nio.ByteBuffer;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * BlockChain is responsible for managing the block chain.  It validates blocks and the
 * transactions they contain.  If the block passes verification, it is stored in the block
 * store and made available when forming a new block chain head.  If the block fails
 * verification, it is still stored in the block store but it is marked as held.  The
 * hold will be removed if a later block removes the reason for the hold.
 */
public class BlockChain {

    /** Logger instance */
    private static final Logger log = LoggerFactory.getLogger(BlockChain.class);

    /** Verify blocks */
    private boolean verifyBlocks;

    /** Chain listeners */
    private List<ChainListener> listeners = new LinkedList<>();

    /**
     * Creates a new block chain
     *
     * @param       verifyBlocks    TRUE if new blocks should be verified
     */
    public BlockChain(boolean verifyBlocks) {
        this.verifyBlocks = verifyBlocks;
    }

    /**
     * Registers a chain listener
     *
     * @param       chainListener   The chain listener
     */
    public void addListener(ChainListener chainListener) {
        listeners.add(chainListener);
    }

    /**
     * Returns a block from the database or a block archive file
     *
     * @param       blockHash       Block hash
     * @return      The requested block or null if the block is not found
     * @throws      BlockStoreException Unable to retrieve the block from the database
     */
    public Block getBlock(Sha256Hash blockHash) throws BlockStoreException {
        return Parameters.blockStore.getBlock(blockHash);
    }

    /**
     * Adds a block to the block store and updates the block chain
     *
     * @param       block           The block to add
     * @return      List of blocks that have been added to the chain.  The first element in the list
     *              is the junction block and will not contain any block data.  The list will
     *              be null if no blocks have been added to the chain.
     * @throws      BlockStoreException Unable to store the block in the database
     */
    public List<StoredBlock> storeBlock(Block block) throws BlockStoreException {
        //
        // Store the block in the database with hold status until we have verified the block
        //
        StoredBlock storedBlock = new StoredBlock(block, BigInteger.ZERO, 0);
        storedBlock.setHold(true);
        Parameters.blockStore.storeBlock(storedBlock);
        //
        // Notify listeners that a new block has been added to the block store
        //
        for (ChainListener listener : listeners)
            listener.blockStored(storedBlock);
        //
        // Update the block chain
        //
        return updateBlockChain(storedBlock);
    }

    /**
     * Updates the block chain to reflect a new or updated block.
     * The block must be in the block store and must be on hold if this
     * is a new block that hasn't been verified yet.
     *
     * @param       storedBlock         The new or updated stored block
     * @return                          List of blocks that have been added to the chain.
     *                                  The first element in the list is the junction block
     *                                  and will not contain any block data.  The list will
     *                                  be null if no blocks have been added to the chain.
     * @throws      BlockStoreException Unable to update the block chain in the database
     */
    public List<StoredBlock> updateBlockChain(StoredBlock storedBlock) throws BlockStoreException {
        List<StoredBlock> chainList = null;
        Map<Sha256Hash, Transaction> txMap = null;
        Map<Sha256Hash, List<StoredOutput>> outputMap = null;
        boolean onHold = false;
        Block block = storedBlock.getBlock();
        //
        // Locate the chain containing this block and map the transactions in the chain.
        // We will need this information when validating transactions since these transactions
        // are not in the database yet.
        //
        // A BlockNotFoundException is thrown if a block in the chain is not in the database.
        // This can happen if we receive blocks out-of-order.  In this case, we need to place
        // the new block on hold until we receive another block in the chain.  We will add
        // the missing block to the list of blocks to be fetched from a peer.
        //
        // A ChainTooLongException is thrown if the block chain exceeds 144 blocks.  This is
        // done to avoid running out of storage as the unresolved chain increases in size.
        // The exception contains the hash for the restart block.  We will recursively call
        // ourself to work our way down to the junction block.
        //
        try {
            chainList = Parameters.blockStore.getJunction(block.getPrevBlockHash());
            txMap = new HashMap<>(chainList.size());
            outputMap = new HashMap<>(chainList.size()*250);
            for (StoredBlock chainStoredBlock : chainList) {
                Block chainBlock = chainStoredBlock.getBlock();
                if (chainBlock != null) {
                    List<Transaction> txList = chainBlock.getTransactions();
                    for (Transaction tx : txList)
                        txMap.put(tx.getHash(), tx);
                }
            }
            List<Transaction> txList = block.getTransactions();
            for (Transaction tx : txList)
                txMap.put(tx.getHash(), tx);
        } catch (ChainTooLongException exc) {
            onHold = true;
            Sha256Hash chainHash = exc.getHash();
            StoredBlock chainStoredBlock = Parameters.blockStore.getStoredBlock(chainHash);
            chainList = updateBlockChain(chainStoredBlock);
        } catch (BlockNotFoundException exc) {
            onHold = true;
            PeerRequest request = new PeerRequest(exc.getHash(), Parameters.INV_BLOCK);
            synchronized(Parameters.lock) {
                Parameters.pendingRequests.add(request);
            }
            Parameters.networkListener.wakeup();
        }
        //
        // The new block must have a target difficulty that is equal to or less than the
        // previous block in the chain (the target difficulty decreases as the work required increases)
        // Blocks were added to the block chain before this test was implemented, so we need to
        // allow old blocks even if they fail this test.
        //
        if (!onHold && Parameters.blockStore.getChainHeight() >= 150000) {
            BigInteger blockDiff = block.getTargetDifficultyAsInteger();
            BigInteger chainDiff;
            Block chainBlock = chainList.get(chainList.size()-1).getBlock();
            if (chainBlock != null)
                chainDiff = chainBlock.getTargetDifficultyAsInteger();
            else
                chainDiff = Parameters.blockStore.getTargetDifficulty();
            if (blockDiff.compareTo(chainDiff) > 0) {
                log.error(String.format("Block target difficulty is greater than chain target difficulty\n  Block %s",
                                        block.getHashAsString()));
                onHold = true;
            }
        }
        //
        // The block version must be 2 (or greater) if the chain height is 250,000 or greater
        //
        if (!onHold) {
            long version = block.getVersion();
            if (Parameters.blockStore.getChainHeight() >= 250000 && version < 2) {
                log.error(String.format("Block version %d is not valid", version));
                onHold = true;
            }
        }
        //
        // Check for any held blocks in the chain.  If we find one, attempt to verify it.
        // If the verification fails, we will need to wait until another block is received
        // before we can try to verify the chain again.
        //
        if (!onHold) {
            BigInteger chainWork = chainList.get(0).getChainWork();
            int chainHeight = chainList.get(0).getHeight();
            for (StoredBlock chainStoredBlock : chainList) {
                Block chainBlock = chainStoredBlock.getBlock();
                if (chainBlock != null) {
                    chainWork = chainWork.add(chainBlock.getWork());
                    chainStoredBlock.setChainWork(chainWork);
                    chainStoredBlock.setHeight(++chainHeight);
                    if (chainStoredBlock.isOnHold()) {
                        if (verifyBlocks) {
                            if (!verifyBlock(chainStoredBlock, chainList.get(0).getHeight(), txMap, outputMap)) {
                                log.info(String.format("Failed to verify held block\n  Block %s",
                                                       chainBlock.getHashAsString()));
                                onHold = true;
                                break;
                            }
                        }
                        chainStoredBlock.setHold(false);
                        Parameters.blockStore.releaseBlock(chainStoredBlock.getHash());
                        log.info(String.format(String.format("Held block released\n  Block %s",
                                                             chainBlock.getHashAsString())));
                        for (ChainListener listener : listeners)
                            listener.blockUpdated(chainStoredBlock);
                    }
                }
            }
            //
            // Update the new block
            //
            chainWork = chainWork.add(block.getWork());
            storedBlock.setChainWork(chainWork);
            storedBlock.setHeight(++chainHeight);
        }
        //
        // Verify the transactions for the new block
        //
        if (!onHold && verifyBlocks) {
            if (!verifyBlock(storedBlock, chainList.get(0).getHeight(), txMap, outputMap)) {
                log.info(String.format("Block verification failed\n  Block %s",
                                       storedBlock.getHash().toString()));
                onHold = true;
            }
        }
        //
        // Stop now if the block is not ready for processing
        //
        if (onHold)
            return null;
        //
        // Add this block to the end of the chain
        //
        chainList.add(storedBlock);
        //
        // Release the block and update the chain work and block height values in the database
        //
        storedBlock.setHold(false);
        Parameters.blockStore.releaseBlock(storedBlock.getHash());
        for (ChainListener listener : listeners)
            listener.blockUpdated(storedBlock);
        //
        // Make this block the new chain head if it is a better chain than the current chain.
        // This means the cumulative chain work is greater.
        //
        if (storedBlock.getChainWork().compareTo(Parameters.blockStore.getChainWork()) > 0) {
            try {
                Parameters.blockStore.setChainHead(chainList);
                for (StoredBlock updatedStoredBlock : chainList) {
                    Block updatedBlock = updatedStoredBlock.getBlock();
                    if (updatedBlock == null)
                        continue;
                    //
                    // Notify listeners that we updated the block
                    //
                    updatedStoredBlock.setChain(true);
                    for (ChainListener listener : listeners)
                        listener.blockUpdated(updatedStoredBlock);
                    //
                    // Get any orphan transactions that are waiting for transactions in this block
                    //
                    List<StoredTransaction> retryList = new LinkedList<>();
                    List<Transaction> txList = updatedBlock.getTransactions();
                    synchronized(Parameters.lock) {
                        for (Transaction tx : txList) {
                            List<StoredTransaction> orphanList =
                                            Parameters.orphanTxMap.remove(tx.getHash());
                            if (orphanList != null) {
                                for (StoredTransaction orphan : orphanList) {
                                    Parameters.orphanTxList.remove(orphan);
                                    retryList.add(orphan);
                                }
                            }
                        }
                    }
                    //
                    // Retry transactions that are still not in the database
                    //
                    for (StoredTransaction orphan : retryList) {
                        if (Parameters.blockStore.isNewTransaction(orphan.getHash())) {
                            Transaction tx = orphan.getTransaction();
                            TransactionMessage.retryOrphanTransaction(tx);
                        }
                    }
                }
                //
                // Notify listeners that the block chain has been updated
                //
                for (ChainListener listener : listeners)
                    listener.chainUpdated();
            } catch (VerificationException exc) {
                chainList = null;
                log.info(String.format("Block being held due to verification failure\n  Block %s",
                                       exc.getHash().toString()));
            }
        }
        return chainList;
    }

    /**
     * Verify a block
     *
     * @param       block           Block to be verified
     * @param       junctionHeight  Height of the junction block
     * @param       txMap           Transaction map
     * @param       outputMap       Transaction output map
     * @return      TRUE if the block is verified, FALSE otherwise
     * @throws      BlockStoreException  Unable to read from database
     */
    private boolean verifyBlock(StoredBlock storedBlock, int junctionHeight,
                                    Map<Sha256Hash, Transaction> txMap,
                                    Map<Sha256Hash, List<StoredOutput>> outputMap)
                                    throws BlockStoreException {
        Block block = storedBlock.getBlock();
        boolean txValid = true;
        BigInteger totalFees = BigInteger.ZERO;
        //
        // Check each transaction in the block
        //
        List<Transaction> txList = block.getTransactions();
        for (Transaction tx : txList) {
            //
            // The transaction version must be 1 if the block version is 2 (BIP0034)
            //
            if (block.getVersion() >= 2 && tx.getVersion() != 1) {
                log.error(String.format("Transaction version %d is not valid", tx.getVersion()));
                txValid = false;
                break;
            }
            //
            // The input script for the coinbase transaction must contain the chain height
            // as the first data element if the block version is 2 (BIP0034)
            //
            if (tx.isCoinBase()) {
                if (block.getVersion() >= 2 && junctionHeight >= 250000) {
                    TransactionInput input = tx.getInputs().get(0);
                    byte[] scriptBytes = input.getScriptBytes();
                    if (scriptBytes.length < 1) {
                        log.error("Coinbase input script is not valid");
                        txValid = false;
                        break;
                    }
                    int length = (int)scriptBytes[0]&0xff;
                    if (length+1 > scriptBytes.length) {
                        log.error("Coinbase script is too short");
                        txValid = false;
                        break;
                    }
                    int chainHeight = (int)scriptBytes[1]&0xff;
                    for (int i=1; i<length; i++)
                        chainHeight = chainHeight | (((int)scriptBytes[i+1]&0xff)<<(i*8));
                    if (chainHeight != storedBlock.getHeight()) {
                        log.error(String.format("Coinbase height %d does not match block height %d",
                                                chainHeight, storedBlock.getHeight()));
                        Main.dumpData("Coinbase Script", scriptBytes);
                        txValid = false;
                        break;
                    }
                }
                continue;
            }
            //
            // Check each input in the transaction
            //
            BigInteger txAmount = BigInteger.ZERO;
            List<TransactionInput> inputs = tx.getInputs();
            for (TransactionInput input : inputs) {
                OutPoint op = input.getOutPoint();
                Sha256Hash opHash = op.getHash();
                int opIndex = op.getIndex();
                //
                // Locate the connected transaction output
                //
                List<StoredOutput> outputs = outputMap.get(opHash);
                if (outputs == null) {
                    Transaction outTx = txMap.get(opHash);
                    if (outTx == null) {
                        outputs = Parameters.blockStore.getTxOutputs(opHash);
                        if (outputs == null) {
                            log.error(String.format("Transaction input specifies unavailable transaction\n"+
                                                    "  Transaction %s\n  Transaction input %d\n  Connected output %s",
                                                    tx.getHash().toString(), input.getIndex(),
                                                    opHash.toString()));
                            txValid = false;
                        } else {
                            outputMap.put(opHash, outputs);
                        }
                    } else {
                        List<TransactionOutput> txOutputList = outTx.getOutputs();
                        outputs = new ArrayList<>(txOutputList.size());
                        for (TransactionOutput txOutput : txOutputList)
                            outputs.add(new StoredOutput(txOutput.getIndex(), txOutput.getValue(),
                                                         txOutput.getScriptBytes()));
                        outputMap.put(opHash,outputs);
                    }
                }
                //
                // Add the input amount to the running total for the transaction.
                // Verify the input signature against the connected output.  We allow a double-spend
                // if the spending block is above the junction block since that spending block will
                // be removed if the chain ends up being reorganized.
                //
                if (txValid) {
                    StoredOutput output = null;
                    boolean foundOutput = false;
                    for (int i=0; i<outputs.size(); i++) {
                        output = outputs.get(i);
                        if (output.getIndex() == opIndex) {
                            foundOutput = true;
                            break;
                        }
                    }
                    if (!foundOutput) {
                        log.error(String.format("Transaction input specifies non-existent output\n"+
                                                "  Transaction %s\n  Transaction input %d\n"+
                                                "  Connected output %s\n  Connected output index %d",
                                                tx.getHash().toString(), input.getIndex(),
                                                opHash.toString(), opIndex));
                        byte[] txData = tx.getBytes();
                        Main.dumpData("Failing Transaction", txData, txData.length);
                        txValid = false;
                    } else {
                        if (output.isSpent() && output.getHeight() != 0 && output.getHeight() <= junctionHeight) {
                            log.error(String.format("Transaction input specifies spent output\n"+
                                                    "  Transaction %s\n  Transaction intput %d\n"+
                                                    "  Connected output %s\n  Connected output index %d",
                                                    tx.getHash().toString(), input.getIndex(),
                                                    opHash.toString(), opIndex));
                            txValid = false;
                        } else {
                            txAmount = txAmount.add(output.getValue());
                            output.setSpent(true);
                            output.setHeight(storedBlock.getHeight());
                            txValid = tx.verifyInput(input, output.getScriptBytes());
                            if (!txValid)
                                log.error(String.format("Transaction failed signature verification\n"+
                                                        "  Transaction %s\n  Transaction input %d\n"+
                                                        "  Outpoint %s\n  Outpoint index %d",
                                                        tx.getHash().toString(), input.getIndex(),
                                                        op.getHash().toString(), op.getIndex()));
                        }
                    }
                }
                //
                // Stop processing transaction inputs if this input failed to verify
                //
                if (!txValid)
                    break;
            }
            //
            // Get the amount for each output and subtract it from the transaction total
            //
            if (txValid) {
                List<TransactionOutput> outputs = tx.getOutputs();
                for (TransactionOutput output : outputs)
                    txAmount = txAmount.subtract(output.getValue());
                if (txAmount.compareTo(BigInteger.ZERO) < 0) {
                    log.error(String.format("Transaction inputs less than transaction outputs\n  %s",
                                            tx.getHash().toString()));
                    txValid = false;
                } else {
                    totalFees = totalFees.add(txAmount);
                }
            }
            //
            // Stop processing the block transactions if we already have a failed transaction
            //
            if (!txValid)
                break;
        }
        //
        // The coinbase amount must not exceed the block reward plus the transaction fees for the block.
        // The block reward starts at 50 BTC and is cut in half every 210,000 blocks.
        //
        if (txValid) {
            long divisor = 1<<((storedBlock.getHeight())/210000);
            BigInteger blockReward = BigInteger.valueOf(5000000000L).divide(BigInteger.valueOf(divisor));
            Transaction tx = block.getTransactions().get(0);
            List<TransactionOutput> outputs = tx.getOutputs();
            BigInteger txAmount = blockReward.add(totalFees);
            for (TransactionOutput output : outputs)
                txAmount = txAmount.subtract(output.getValue());
            if (txAmount.compareTo(BigInteger.ZERO) < 0) {
                log.error(String.format("Coinbase transaction outputs exceed block reward plus fees\n %s",
                                        block.getHashAsString()));
                txValid = false;
            }
        }
        return txValid;
    }
}
