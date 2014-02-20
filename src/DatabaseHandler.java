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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * The database handler processes blocks placed on the database queue.  When a
 * block is received, the database handler validates the block and adds it
 * to the database.  This can result in the block chain being reorganized because
 * a better chain is now available.
 *
 * The database handler terminates when its shutdown() method is called.
 */
public class DatabaseHandler implements Runnable {

    /** Logger instance */
    private static final Logger log = LoggerFactory.getLogger(DatabaseHandler.class);

    /** Database handler thread */
    private Thread databaseThread;

    /** Database shutdown */
    private boolean databaseShutdown = false;

    /**
     * Creates the database listener
     */
    public DatabaseHandler() {
    }

    /**
     * Starts the database listener running
     */
    @Override
    public void run() {
        log.info("Database handler started");
        databaseThread = Thread.currentThread();
        //
        // Process blocks until the shutdown() method is called
        //
        try {
            while (!databaseShutdown) {
                Block block = Parameters.databaseQueue.take();
                processBlock(block);
            }
        } catch (InterruptedException exc) {
            if (!databaseShutdown)
                log.warn("Database handler interrupted", exc);
        } catch (Exception exc) {
            log.error("Exception while processing blocks", exc);
        }
        //
        // Stopping
        //
        log.info("Database handler stopped");
    }

    /**
     * Shuts down the database listener
     */
    public void shutdown() {
        databaseShutdown = true;
        databaseThread.interrupt();
    }

    /**
     * Process a block
     *
     * @param       block           Block to process
     */
    private void processBlock(Block block) {
        PeerRequest request = null;
        try {
            //
            // Mark the associated request as being processed so it won't timeout while
            // we are working on it
            //
            synchronized(Parameters.lock) {
                for (PeerRequest chkRequest : Parameters.processedRequests) {
                    if (chkRequest.getType()==Parameters.INV_BLOCK &&
                                                chkRequest.getHash().equals(block.getHash())) {
                        chkRequest.setProcessing(true);
                        request = chkRequest;
                        break;
                    }
                }
            }
            //
            // Process the new block
            //
            if (Parameters.blockStore.isNewBlock(block.getHash())) {
                //
                // Store the block in our database
                //
                List<StoredBlock> chainList = Parameters.blockChain.storeBlock(block);
                //
                // Notify our peers that we have added new blocks to the chain and then
                // see if we have a child block which can now be processed.  To avoid
                // flooding peers with blocks they have already seen, we won't send an
                // 'inv' message if we are more than 3 blocks behind the best network chain.
                //
                if (chainList != null) {
                    for (StoredBlock storedBlock : chainList) {
                        if (storedBlock.getBlock() != null) {
                            int chainHeight = storedBlock.getHeight();
                            Parameters.networkChainHeight = Math.max(chainHeight, Parameters.networkChainHeight);
                            if (chainHeight >= Parameters.networkChainHeight-3)
                                notifyPeers(storedBlock);
                        }
                    }
                    processChildBlock(chainList.get(chainList.size()-1));
                }
            }
            //
            // Remove the request from the processedRequests list
            //
            if (request != null) {
                synchronized(Parameters.lock) {
                    Parameters.processedRequests.remove(request);
                }
            }
        } catch (BlockStoreException exc) {
            log.error(String.format("Unable to store block in database\n  %s",
                                    block.getHashAsString()), exc);
            databaseShutdown = true;
        }
    }

    /**
     * Process a child block and see if it can now be added to the chain
     *
     * @param       storedBlock         The updated block
     * @throws      BlockStoreException
     */
    private void processChildBlock(StoredBlock storedBlock) throws BlockStoreException {
        StoredBlock childStoredBlock = Parameters.blockStore.getChildStoredBlock(storedBlock.getHash());
        if (childStoredBlock != null && !childStoredBlock.isOnChain()) {
            //
            // Update the chain with the child block
            //
            Parameters.blockChain.updateBlockChain(childStoredBlock);
            if (childStoredBlock.isOnChain()) {
                //
                // Notify our peers about this block.  To avoid
                // flooding peers with blocks they have already seen, we won't send an
                // 'inv' message if we are more than 3 blocks behind the best network chain.
                //
                int chainHeight = childStoredBlock.getHeight();
                Parameters.networkChainHeight = Math.max(chainHeight, Parameters.networkChainHeight);
                if (chainHeight >= Parameters.networkChainHeight-3)
                    notifyPeers(childStoredBlock);
                //
                // See if we have another child block which can now be processed
                //
                processChildBlock(childStoredBlock);
            }
        }
    }

    /**
     * Notify peers when a block has been added to the chain
     *
     * @param       storedBlock     The stored block added to the chain
     */
    private void notifyPeers(StoredBlock storedBlock) {
        Block block = storedBlock.getBlock();
        List<Sha256Hash> blockList = new ArrayList<>(1);
        blockList.add(block.getHash());
        Message invMsg = InventoryMessage.buildInventoryMessage(null, Parameters.INV_BLOCK, blockList);
        Parameters.networkListener.broadcastMessage(invMsg);
    }
}
