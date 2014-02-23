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

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;

import java.math.BigInteger;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * BlockStore manages the database used to store blocks and transactions.  The database is
 * periodically pruned to remove spent transaction outputs.
 *
 * The database contains the information for blocks and transactions needed to process new blocks.
 * The actual blocks are stored in external files named 'blknnnnn.dat' located in the Blocks
 * subdirectory.  When the current file reaches the maximum size, the file number is incremented
 * and a new file is created.
 */
public abstract class BlockStore {

    /** Logger instance */
    protected static final Logger log = LoggerFactory.getLogger(BlockStore.class);

    /** Maximum block file size */
    protected static final long MAX_BLOCK_FILE_SIZE = 256 * 1024 * 1024;

    /** Maximum age (seconds) of spent transactions in the transaction outputs table */
    protected static final long MAX_TX_AGE = 1 * 24 * 60 * 60;

    /** Block chain checkpoints */
    protected static final Map<Integer, Sha256Hash> checkpoints = new HashMap<>();
    static {
        checkpoints.put(Integer.valueOf(50000),
                        new Sha256Hash("000000001aeae195809d120b5d66a39c83eb48792e068f8ea1fea19d84a4278a"));
        checkpoints.put(Integer.valueOf(75000),
                        new Sha256Hash("00000000000ace2adaabf1baf9dc0ec54434db11e9fd63c1819d8d77df40afda"));
        checkpoints.put(Integer.valueOf(91722),
                        new Sha256Hash("00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e"));
        checkpoints.put(Integer.valueOf(91812),
                        new Sha256Hash("00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f"));
        checkpoints.put(Integer.valueOf(91842),
                        new Sha256Hash("00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"));
        checkpoints.put(Integer.valueOf(91880),
                        new Sha256Hash("00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721"));
        checkpoints.put(Integer.valueOf(100000),
                        new Sha256Hash("000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506"));
        checkpoints.put(Integer.valueOf(125000),
                        new Sha256Hash("00000000000042391c3620056af66ca9ad7cb962424a9b34611915cebb9e1a2a"));
        checkpoints.put(Integer.valueOf(150000),
                        new Sha256Hash("0000000000000a3290f20e75860d505ce0e948a1d1d846bec7e39015d242884b"));
        checkpoints.put(Integer.valueOf(175000),
                        new Sha256Hash("00000000000006b975c097e9a5235de03d9024ddb205fd24dfcd508403fa907c"));
        checkpoints.put(Integer.valueOf(200000),
                        new Sha256Hash("000000000000034a7dedef4a161fa058a2d67a173a90155f3a2fe6fc132e0ebf"));
        checkpoints.put(Integer.valueOf(225000),
                        new Sha256Hash("000000000000013d8781110987bf0e9f230e3cc85127d1ee752d5dd014f8a8e1"));
        checkpoints.put(Integer.valueOf(250000),
                        new Sha256Hash("000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214"));
        checkpoints.put(Integer.valueOf(275000),
                        new Sha256Hash("00000000000000044750d80a0d3f3e307e54e8802397ae840d91adc28068f5bc"));
    }

    /** Database update lock */
    protected final Object lock = new Object();

    /** Application data path */
    protected String dataPath;

    /** Chain update time */
    protected long chainTime;

    /** Chain head */
    protected Sha256Hash chainHead;

    /** Block preceding the chain head */
    protected Sha256Hash prevChainHead;

    /** Target difficulty */
    protected long targetDifficulty;

    /** Current chain height */
    protected int chainHeight;

    /** Current chain work */
    protected BigInteger chainWork;

    /** Current block file number */
    protected int blockFileNumber;

    /**
     * Creates a BlockStore
     *
     * @param       dataPath            Application data path
     */
    public BlockStore(String dataPath) {
        this.dataPath = dataPath;
        //
        // Create the Blocks subdirectory if it doesn't exist
        //
        File blocksDir = new File(dataPath+"\\Blocks");
        if (!blocksDir.exists())
            blocksDir.mkdirs();
    }

    /**
     * Closes the database
     */
    public abstract void close();

    /**
     * Returns the block hash for the current chain head
     *
     * @return      Chain head block hash
     */
    public Sha256Hash getChainHead() {
        return chainHead;
    }

    /**
     * Returns the current chain height
     *
     * @return      Current chain height
     */
    public int getChainHeight() {
        return chainHeight;
    }

    /**
     * Returns the current target difficulty as a BigInteger
     *
     * @return      Target difficulty
     */
    public BigInteger getTargetDifficulty() {
        return Utils.decodeCompactBits(targetDifficulty);
    }

    /**
     * Returns the current chain work
     *
     * @return      Current chain work
     */
    public BigInteger getChainWork() {
        return chainWork;
    }

    /**
     * Checks if the block is already in our database
     *
     * @param       blockHash               The block to check
     * @return                              TRUE if this is a new block
     * @throws      BlockStoreException     Unable to check the block status
     */
    public abstract boolean isNewBlock(Sha256Hash blockHash) throws BlockStoreException;

    /**
     * Checks if the alert is already in our database
     *
     * @param       alertID                 Alert identifier
     * @return                              TRUE if this is a new alert
     * @throws      BlockStoreException     Unable to get the alert status
     */
    public abstract boolean isNewAlert(int alertID) throws BlockStoreException;

    /**
     * Returns a list of all alerts in the database
     *
     * @return                              List of all alerts
     * @throws      BlockStoreException     Unable to get alerts from database
     */
    public abstract List<Alert> getAlerts() throws BlockStoreException;

    /**
     * Stores an alert in the database
     *
     * @param       alert                   The alert
     * @throws      BlockStoreException     Unable to store the alert
     */
    public abstract void storeAlert(Alert alert) throws BlockStoreException;

    /**
     * Cancels an alert
     *
     * @param       alertID                 The alert identifier
     * @throws      BlockStoreException     Unable to update the alert
     */
    public abstract void cancelAlert(int alertID) throws BlockStoreException;

    /**
     * Checks if the block is on the main chain
     *
     * @param       blockHash               The block to check
     * @return                              TRUE if the block is on the main chain
     * @throws      BlockStoreException     Unable to get the block status
     */
    public abstract boolean isOnChain(Sha256Hash blockHash) throws BlockStoreException;

    /**
     * Returns a block that was stored in the database.  The returned block represents the
     * block data sent over the wire and does not include any information about the
     * block location within the block chain.
     *
     * @param       blockHash               Block hash
     * @return                              The block or null if the block is not found
     * @throws      BlockStoreException     Unable to get block from database
     */
    public abstract Block getBlock(Sha256Hash blockHash) throws BlockStoreException;

    /**
     * Returns a block that was stored in the database.  The returned block contains
     * the basic block plus information about its current location within the block chain.
     *
     * @param       blockHash               The block hash
     * @return                              The stored block or null if the block is not found
     * @throws      BlockStoreException     Unable to get block from database
     */
    public abstract StoredBlock getStoredBlock(Sha256Hash blockHash) throws BlockStoreException;

    /**
     * Returns the child block for the specified block
     *
     * @param       blockHash               The block hash
     * @return                              The stored block or null if the block is not found
     * @throws      BlockStoreException     Unable to get block
     */
    public abstract StoredBlock getChildStoredBlock(Sha256Hash blockHash) throws BlockStoreException;

    /**
     * Returns the block status for recent blocks
     *
     * @param       maxCount                The maximum number of blocks to be returned
     * @return                              A list of BlockStatus objects
     * @throws      BlockStoreException     Unable to get block status
     */
    public abstract List<BlockStatus> getBlockStatus(int maxCount) throws BlockStoreException;

    /**
     * Check if this is a new transaction
     *
     * @param       txHash                  Transaction hash
     * @return                              TRUE if the transaction is not in the database
     * @throws      BlockStoreException     Unable to check transaction status
     */
    public abstract boolean isNewTransaction(Sha256Hash txHash) throws BlockStoreException;

    /**
     * Returns the requested transaction output
     *
     * @param       outPoint                Transaction outpoint
     * @return                              Transaction output or null if the transaction is not found
     * @throws      BlockStoreException     Unable to get transaction output status
     */
    public abstract StoredOutput getTxOutput(OutPoint outPoint) throws BlockStoreException;

    /**
     * Returns the outputs for the specified transaction
     *
     * @param       txHash                  Transaction hash
     * @return                              Stored output list
     * @throws      BlockStoreException     Unable to get transaction outputs
     */
    public abstract List<StoredOutput> getTxOutputs(Sha256Hash txHash) throws BlockStoreException;

    /**
     * Returns the chain list from the block following the start block up to the stop
     * block.  A maximum of 500 blocks will be returned.  The list will start with the
     * genesis block if the start block is not found.
     *
     * @param       startBlock              The start block
     * @param       stopBlock               The stop block
     * @return                              Block hash list
     * @throws      BlockStoreException     Unable to get blocks from database
     */
    public abstract List<Sha256Hash> getChainList(Sha256Hash startBlock, Sha256Hash stopBlock)
                                        throws BlockStoreException;

    /**
     * Returns the chain list from the block following the start block up to the stop
     * block.  A maximum of 500 blocks will be returned.
     *
     * @param       startHeight             Start block height
     * @param       stopBlock               Stop block
     * @return                              Block hash list
     * @throws      BlockStoreException     Unable to get blocks from database
     */
    public abstract List<Sha256Hash> getChainList(int startHeight, Sha256Hash stopBlock)
                                        throws BlockStoreException;

    /**
     * Returns the header list from the block following the start block up to the stop
     * block.  A maximum of 2000 blocks will be returned.  The list will start with the
     * genesis block if the start block is not found.  The returned header will include
     * the block header plus the encoded transaction count.
     *
     * @param       startBlock              The start block
     * @param       stopBlock               The stop block
     * @return                              Block header list (includes the transaction count)
     * @throws      BlockStoreException     Unable to get data from the database
     */
    public abstract List<byte[]> getHeaderList(Sha256Hash startBlock, Sha256Hash stopBlock)
                                        throws BlockStoreException;

    /**
     * Releases a held block for processing
     *
     * @param       blockHash               Block hash
     * @throws      BlockStoreException     Unable to release the block
     */
    public abstract void releaseBlock(Sha256Hash blockHash) throws BlockStoreException;

    /**
     * Stores a block in the database
     *
     * @param       storedBlock             Block to be stored
     * @throws      BlockStoreException     Unable to store the block
     */
    public abstract void storeBlock(StoredBlock storedBlock) throws BlockStoreException;

    /**
     * Cleans up the database tables by deleting transaction outputs that are older
     * than the age limit
     *
     * @param       forcePurge              Purge entries even if the age limit hasn't been reached
     * @throws      BlockStoreException     Unable to delete transaction outputs
     */
    public abstract void cleanupDatabase(boolean forcePurge) throws BlockStoreException;

    /**
     * Locates the junction where the chain represented by the specified block joins
     * the current block chain.  The returned list starts with the junction block
     * and contains all blocks in the chain leading to the specified block.
     * The StoredBlock object for the junction block will not contain a Block object while
     * the StoredBlock objects for the blocks in the new chain will contain Block objects.
     *
     * A BlockNotFoundException will be thrown if the chain cannot be resolved because a
     * block is missing.  The caller should get the block from a peer, store it in the
     * database and then retry.
     *
     * A ChainTooLongException will be thrown if the block chain is getting too big.  The
     * caller should restart the chain resolution closer to the junction block and then
     * work backwards toward the original block.
     *
     * @param       chainHash                   The block hash of the chain head
     * @throws      BlockNotFoundException      A block in the chain was not found
     * @throws      BlockStoreException         Unable to get blocks from the database
     * @throws      ChainTooLongException       The block chain is too long
     */
    public abstract List<StoredBlock> getJunction(Sha256Hash chainHash)
                         throws BlockNotFoundException, BlockStoreException, ChainTooLongException;

    /**
     * Changes the chain head and updates all blocks from the junction block up to the new
     * chain head.  The junction block is the point where the current chain and the new
     * chain intersect.  A VerificationException will be thrown if a block in the new chain is
     * for a checkpoint block and the block hash doesn't match the checkpoint hash.
     *
     * @param       chainList                   List of all chain blocks starting with the junction block
     *                                          up to and including the new chain head
     * @throws      BlockStoreException         Unable to update the database
     * @throws      VerificationException       Chain verification failed
     */
    public abstract void setChainHead(List<StoredBlock> chainList)
                                            throws BlockStoreException, VerificationException;

    /**
     * Returns a block that was stored in one of the block files
     *
     * @param       fileNumber          The block file number
     * @param       fileOffset          The block offset within the file
     * @return                          The requested block or null if the block is not found
     * @throws      BlockStoreException Unable to read the block data
     */
    protected Block getBlock(int fileNumber, int fileOffset) throws BlockStoreException {
        if (fileNumber < 0)
            throw new BlockStoreException(String.format("Invalid file number %d", fileNumber));
        Block block = null;
        File blockFile = new File(String.format("%s\\Blocks\\blk%05d.dat", dataPath, fileNumber));
        try {
            try (RandomAccessFile inFile = new RandomAccessFile(blockFile, "r")) {
                inFile.seek(fileOffset);
                byte[] bytes = new byte[8];
                int count = inFile.read(bytes);
                if (count != 8) {
                    log.error(String.format("End-of-data reading from block file %d, offset %d",
                                            fileNumber, fileOffset));
                    throw new BlockStoreException("Unable to read block file");
                }
                long magic = Utils.readUint32LE(bytes, 0);
                int length = (int)Utils.readUint32LE(bytes, 4);
                if (magic != Parameters.MAGIC_NUMBER) {
                    log.error(String.format("Magic number %X is incorrect in block file %d, offset %d",
                                            magic, fileNumber, fileOffset));
                    throw new BlockStoreException("Incorrect block file format");
                }
                if (length < Block.HEADER_SIZE) {
                    log.error(String.format("Block length %d is too small in block file %d, offset %d",
                                            length, fileNumber, fileOffset));
                    throw new BlockStoreException("Incorrect block length");
                }
                byte[] blockData = new byte[length];
                count = inFile.read(blockData);
                if (count != length) {
                    log.error(String.format("End-of-data reading block file %d, offset %d",
                                            fileNumber, fileOffset));
                    throw new BlockStoreException("Unable to read block file");
                }
                block = new Block(blockData, 0, length, false);
            }
        } catch (IOException | VerificationException exc) {
            log.error(String.format("Unable to read block file %d, offset %d",
                                    fileNumber, fileOffset), exc);
            throw new BlockStoreException("Unable to read block file");
        }
        return block;
    }

    /**
     * Stores a block in the current block file
     *
     * @param       block               Block to store
     * @return                          Array containing the block file number and offset
     * @throws      BlockStoreException Error while writing to the block file
     */
    protected int[] storeBlock(Block block) throws BlockStoreException {
        int[] blockLocation = new int[2];
        try {
            byte[] blockData = block.bitcoinSerialize();
            File blockFile = new File(String.format("%s\\Blocks\\blk%05d.dat", dataPath, blockFileNumber));
            long filePosition = blockFile.length();
            if (filePosition >= MAX_BLOCK_FILE_SIZE) {
                blockFileNumber++;
                filePosition = 0;
                blockFile = new File(String.format("%s\\Blocks\\blk%05d.dat", dataPath, blockFileNumber));
                if (blockFile.exists())
                    blockFile.delete();
            }
            try (RandomAccessFile outFile = new RandomAccessFile(blockFile, "rws")) {
                outFile.seek(filePosition);
                byte[] bytes = new byte[8];
                Utils.uint32ToByteArrayLE(Parameters.MAGIC_NUMBER, bytes, 0);
                Utils.uint32ToByteArrayLE(blockData.length, bytes, 4);
                outFile.write(bytes);
                outFile.write(blockData);
                blockLocation[0] = blockFileNumber;
                blockLocation[1] = (int)filePosition;
            }
        } catch (IOException exc) {
            log.error(String.format("Unable to write to block file %d", blockFileNumber), exc);
            throw new BlockStoreException("Unable to write to block file");
        }
        return blockLocation;
    }

    /**
     * Truncate a block file to recover from a database error
     *
     * @param       fileLocation            The file location returned by storeBlock()
     */
    protected void truncateBlockFile(int[] fileLocation) {
        File blockFile = new File(String.format("%s\\Blocks\\blk%05d.dat", dataPath, fileLocation[0]));
        try {
            //
            // If the block is stored at the beginning of the file, just delete the file
            // and decrement the block number.  Otherwise, truncate the file.
            if (fileLocation[1] == 0) {
                blockFile.delete();
                blockFileNumber--;
            } else {
                try (RandomAccessFile outFile = new RandomAccessFile(blockFile, "rws")) {
                    outFile.getChannel().truncate(fileLocation[1]);
                }
            }
        } catch (IOException exc) {
            log.error(String.format("Unable to truncate block file %d", fileLocation[0]), exc);
        }
    }
}