/**
 * Copyright 2011 Google Inc.
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

import java.io.EOFException;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * <p>The Bitcoin block chain contains all of the transactions that have occurred and is available to everyone.
 * The block chain consists of a series of blocks starting with the genesis block (block 0) and continuing
 * to the chain head (the latest block in the chain).</p>
 *
 * <p>Each block is composed of one or more transactions.  The first transaction is called the coinbase transaction
 * and it assigns the block reward to the miner who solved the block hash.  The remaining transactions move coins
 * from Input A to Output B.  A single transaction can contain multiple inputs and multiple outputs.  The sum of
 * the inputs minus the sum of the output represents the mining fee for that transaction.</p>
 *
 * <p>A block has the following format:</p>
 * <pre>
 *   Size           Field               Description
 *   ====           =====               ===========
 *   80 bytes       BlockHeader         Consists of 6 fields that are hashed to calculate the block hash
 *   VarInt         TxCount             Number of transactions in the block
 *   Variable       Transactions        The transactions in the block
 * </pre>
 *
 * <p>The block header has the following format:</p>
 * <pre>
 *   Size           Field               Description
 *   ====           =====               ===========
 *   4 bytes        Version             The block version number
 *   32 bytes       PrevBlockHash       The hash of the preceding block in the chain
 *   32 byte        MerkleRoot          The Merkle root for the transactions in the block
 *   4 bytes        Time                The time the block was mined
 *   4 bytes        Difficulty          The target difficulty
 *   4 bytes        Nonce               The nonce used to generate the required hash
 *</pre>
 */
public class Block {

    /** Logger instance */
    private static final Logger log = LoggerFactory.getLogger(Block.class);

    /** Block header size */
    public static final int HEADER_SIZE = 80;

    /** The number that is one greater than the largest representable SHA-256 hash */
    private static final BigInteger LARGEST_HASH = BigInteger.ONE.shiftLeft(256);

    /** The serialized byte stream */
    private byte[] blockData;

    /** The block version */
    private long blockVersion;

    /** The block hash calculated from the block header */
    private Sha256Hash blockHash;

    /** The hash for the previous block in the chain */
    private Sha256Hash prevBlockHash;

    /** The Merkle root for the transactions in the block */
    private Sha256Hash merkleRoot;

    /** The Merkle tree for the transaction in the block */
    private List<byte[]> merkleTree;

    /** The block timestamp */
    private long timeStamp;

    /** The target difficulty */
    private long targetDifficulty;

    /** The nonce */
    private long nonce;

    /** The transactions contained in the block */
    private List<Transaction> transactions;

    /**
     * Creates a block from a serialized byte array.  The serialized data starts with the block header.
     *
     * @param       inBytes             Byte array containing the serialized data
     * @param       inOffset            Starting offset within the array
     * @param       inLength            Length of the serialized data
     * @param       doVerify            TRUE if the block structure should be verified
     * @throws      EOFException        Serialized byte stream is too short
     * @throws      IOException         Error reading from the input stream
     * @throws      VerificationException Block verification checks failed
     */
    public Block(byte[] inBytes, int inOffset, int inLength, boolean doVerify)
                                        throws EOFException, IOException, VerificationException {
        //
        // We must have at least 80 bytes
        //
        if (inBytes.length < HEADER_SIZE) {
            log.error(String.format("Serialized data is too short: Required %d, Received %d",
                                    HEADER_SIZE, inBytes.length));
            throw new EOFException("Serialized data too short");
        }
        //
        // Compute the block hash from the serialized block header
        //
        blockHash = new Sha256Hash(Utils.reverseBytes(Utils.doubleDigest(inBytes, inOffset, HEADER_SIZE)));
        //
        // Wrap the byte array in an input stream
        //
        SerializedInputStream inStream = new SerializedInputStream(inBytes, inOffset, inLength);
        //
        // Read the block header
        //
        readHeader(inStream);
        //
        // Read the transactions
        //
        readTransactions(inStream);
        //
        // Verify the block and its transactions.  Note that transaction signatures and connected
        // outputs will be verified when the block is added to the block chain.
        //
        if (doVerify)
            verifyBlock();
        //
        // Save a copy of the serialized byte stream
        //
        blockData = inStream.getBytes(inOffset);
    }

    /**
     * <p>Returns the block version.  Only Version 1 and Version 2 blocks are supported.</p>
     * <ul>
     * <li>Blocks created before BIP 34 are Version 1 and do not contain the chain height
     * in the coinbase transaction input script</li>
     * <li>Blocks created after BIP 34 are Version 2 and contain the chain height in the coinbase
     * transaction input script</li>
     * </ul>
     *
     * @return      Block version
     */
    public long getVersion() {
        return blockVersion;
    }

    /**
     * Returns the time the block was mined
     *
     * @return      The block timestamp in seconds since the Unix epoch (Jan 1, 1970)
     */
    public long getTimeStamp() {
        return timeStamp;
    }

    /**
     * Returns the block hash calculated over the block header
     *
     * @return      Block hash
     */
    public Sha256Hash getHash() {
        return blockHash;
    }

    /**
     * Returns the block hash as a formatted hex string
     *
     * @return      Hex string
     */
    public String getHashAsString() {
        return blockHash.toString();
    }

    /**
     * Returns the hash of the previous block in the chain
     *
     * @return      Previous block hash
     */
    public Sha256Hash getPrevBlockHash() {
        return prevBlockHash;
    }

    /**
     * Returns the Merkle root
     *
     * @return      Merkle root
     */
    public Sha256Hash getMerkleRoot() {
        return merkleRoot;
    }

    /**
     * Returns the Merkle tree
     *
     * @return      Merkle tree
     */
    public List<byte[]> getMerkleTree() {
        if (merkleTree == null)
            merkleTree = buildMerkleTree();
        return merkleTree;
    }

    /**
     * Returns the target difficulty in compact form
     *
     * @return      Target difficulty
     */
    public long getTargetDifficulty() {
        return targetDifficulty;
    }

    /**
     * Returns the target difficulty as a 256-bit value that can be compared to a SHA-256 hash.
     * Inside a block. the target is represented using a compact form.
     *
     * @return      The difficulty target
     */
    public BigInteger getTargetDifficultyAsInteger() {
        return Utils.decodeCompactBits(targetDifficulty);
    }

    /**
     * <p>Returns the work represented by this block.<p>
     *
     * <p>Work is defined as the number of tries needed to solve a block in the
     * average case.  As the target gets lower, the amount of work goes up.</p>
     *
     * @return      The work represented by this block
     */
    public BigInteger getWork() {
        BigInteger target = getTargetDifficultyAsInteger();
        return LARGEST_HASH.divide(target.add(BigInteger.ONE));
    }

    /**
     * Returns the transactions in this block
     *
     * @return      Transaction list
     */
    public List<Transaction> getTransactions() {
        return transactions;
    }

    /**
     * Calculates the Merkle root from the block transactions
     *
     * @return      Merkle root
     */
    private Sha256Hash calculateMerkleRoot() {
        if (merkleTree == null)
            merkleTree = buildMerkleTree();
        return new Sha256Hash(merkleTree.get(merkleTree.size()-1));
    }

    /**
     * Builds the Merkle tree from the block transactions
     *
     * @return      List of byte arrays representing the nodes in the Merkle tree
     */
    private List<byte[]> buildMerkleTree() {
        //
        // The Merkle root is based on a tree of hashes calculated from the transactions:
        //
        //     root
        //      / \
        //   A      B
        //  / \    / \
        // t1  t2 t3  t4
        //
        // The tree is represented as a list: t1,t2,t3,t4,A,B,root where each entry is a hash
        //
        // The hashing algorithm is double SHA-256. The leaves are a hash of the serialized contents of the transaction.
        // The interior nodes are hashes of the concatenation of the two child hashes.
        //
        // This structure allows the creation of proof that a transaction was included into a block without having to
        // provide the full block contents. Instead, you can provide only a Merkle branch. For example to prove tx2 was
        // in a block you can just provide tx2, the hash(tx1) and B. Now the other party has everything they need to
        // derive the root, which can be checked against the block header. These proofs are useful when we
        // want to download partial block contents.
        //
        // Note that if the number of transactions is not even, the last tx is repeated to make it so.
        // A tree with 5 transactions would look like this:
        //
        //          root
        //        /       \
        //       4          5
        //     /  \        / \
        //    1     2     3   3
        //   / \   / \   / \
        //  t1 t2 t3 t4 t5 t5
        //
        ArrayList<byte[]> tree = new ArrayList<>();
        //
        // Start by adding all the hashes of the transactions as leaves of the tree
        //
        for (Transaction tx : transactions)
            tree.add(tx.getHash().getBytes());
        //
        // The tree is generated starting at the leaves and moving down to the root
        //
        int levelOffset = 0;
        //
        // Step through each level, stopping when we reach the root (levelSize == 1).
        //
        for (int levelSize=transactions.size(); levelSize>1; levelSize=(levelSize+1)/2) {
            //
            // Process each pair of nodes on the current level
            //
            for (int left=0; left<levelSize; left+=2) {
                //
                // The right hand node can be the same as the left hand in the case where we have
                // an odd number of nodes for the level
                //
                int right = Math.min(left+1, levelSize-1);
                byte[]leftBytes = Utils.reverseBytes(tree.get(levelOffset+left));
                byte[]rightBytes = Utils.reverseBytes(tree.get(levelOffset+right));
                byte[]nodeHash = Utils.doubleDigestTwoBuffers(leftBytes, 0, 32, rightBytes, 0, 32);
                tree.add(Utils.reverseBytes(nodeHash));
            }
            //
            // Move to the next level.
            //
            levelOffset += levelSize;
        }
        return tree;
    }

    /**
     * Returns the serialized block data
     *
     * @return      Byte array containing the serialized data
     */
    public byte[] bitcoinSerialize() {
        return blockData;
    }

    /**
     * Reads the block header from the input stream
     *
     * @param       inStream            Input stream
     * @throws      EOFException        Serialized input stream is too short
     * @throws      IOException         Error reading from the input stream
     * @throws      VerificationException   Block structure is incorrect
     */
    private void readHeader(SerializedInputStream inStream)
                                        throws EOFException, IOException, VerificationException {
        byte[] bytes = new byte[HEADER_SIZE];
        inStream.read(bytes, 0, HEADER_SIZE);
        blockVersion = Utils.readUint32LE(bytes, 0);
        if (blockVersion != 1 && blockVersion != 2) {
            log.error(String.format("Block version %d is not supported\n  %s",
                                    blockVersion, blockHash.toString()));
            throw new VerificationException("Block version is not supported");
        }
        prevBlockHash = new Sha256Hash(Utils.reverseBytes(bytes, 4, 32));
        merkleRoot = new Sha256Hash(Utils.reverseBytes(bytes, 36, 32));
        timeStamp = Utils.readUint32LE(bytes, 68);
        targetDifficulty = Utils.readUint32LE(bytes, 72);
        nonce = Utils.readUint32LE(bytes, 76);
    }

    /**
     * Reads the transactions from the serialized stream
     *
     * @param       inStream            Serialized input stream
     * @throws      EOFException        Serialized input stream is too short
     * @throws      IOException         Error reading from input stream
     * @throws      VerificationException Transaction verification failed
     */
    private void readTransactions(SerializedInputStream inStream)
                            throws EOFException, IOException, VerificationException {
        int count = new VarInt(inStream).toInt();
        if (count < 1 || count > Parameters.MAX_BLOCK_SIZE/60)
            throw new VerificationException(String.format("Transaction count %d is not valid", count));
        transactions = new ArrayList<>(count);
        for (int i=0; i<count; i++)
            transactions.add(new Transaction(inStream));
    }

    /**
     * <p>Checks the block to ensure it follows the rules laid out in the network parameters.</p>
     * <p>The following checks are performed:</p>
     * <ul>
     * <li>Check the proof of work by comparing the block hash to the target difficulty</li>
     * <li>Check the timestamp against the current time</li>
     * <li>Verify that there is a single coinbase transaction and it is the first transaction
     * in the block</li>
     * <li>Verify the merkle root</li>
     * <li>Verify the transaction structure</li>
     * <li>Verify the transaction lock time</li>
     * </ul>
     *
     * @throws      VerificationException  Block verification failed
     */
    private void verifyBlock() throws VerificationException {
        //
        // Ensure this block does in fact represent real work done.  If the difficulty is high enough,
        // we can be fairly certain the work was done by the network.
        //
        // The block hash must be less than or equal to the target difficulty (the difficulty increases
        // by requiring an increasing number of leading zeroes in the block hash)
        //
        BigInteger target = getTargetDifficultyAsInteger();
        if (target.signum() <= 0 || target.compareTo(Parameters.PROOF_OF_WORK_LIMIT) > 0) {
            log.error(String.format("Target difficulty %s is not valid\n  Block %s",
                                     target.toString(), blockHash.toString()));
            throw new VerificationException("Target difficulty is not valid",
                                            Parameters.REJECT_INVALID, blockHash);
        }
        BigInteger hash = getHash().toBigInteger();
        if (hash.compareTo(target) > 0) {
            log.error(String.format("Block hash is higher than target difficulty\n  Block %s"+
                                    "\n  Block difficulty %s\n  Target difficulty %s",
                                    blockHash.toString(), hash.toString(16), target.toString(16)));
            throw new VerificationException("Block hash is higher than target difficulty",
                                            Parameters.REJECT_INVALID, blockHash);
        }
        //
        // Verify the block timestamp
        //
        long currentTime = System.currentTimeMillis()/1000;
        if (timeStamp > currentTime+Parameters.ALLOWED_TIME_DRIFT) {
            log.error(String.format("Timestamp is too far in the future\n  Block %s"+
                                    "\n  Block time %d\n  Current time %d",
                                    blockHash.toString(), timeStamp, currentTime));
            throw new VerificationException("Block timestamp is too far in the future",
                                            Parameters.REJECT_INVALID, blockHash);
        }
        //
        // Check that there is just one coinbase transaction and it is the first transaction in the block
        //
        boolean foundCoinBase = false;
        for (Transaction tx : transactions) {
            if (tx.isCoinBase()) {
                if (foundCoinBase) {
                    log.error(String.format("Block contains multiple coinbase transactions\n  Block %s",
                                            blockHash.toString()));
                    throw new VerificationException("Block contains multiple coinbase transactions",
                                                    Parameters.REJECT_MALFORMED, blockHash);
                }
                foundCoinBase = true;
            } else if (!foundCoinBase) {
                log.error(String.format("First transaction in block is not the coinbase transaction\n  Block %s",
                                        blockHash.toString()));
                throw new VerificationException("First transaction in block is not the coinbase transaction",
                                                Parameters.REJECT_MALFORMED, blockHash);
            }
        }
        //
        // Verify the Merkle root
        //
        Sha256Hash checkRoot = calculateMerkleRoot();
        if (!checkRoot.equals(merkleRoot)) {
            log.error(String.format("Merkle root is not correct\n  Block %s"+
                                    "\n  Calculated root %s\n  Expected root %s",
                                    blockHash.toString(), checkRoot.toString(), merkleRoot.toString()));
            throw new VerificationException("Merkle root is not correct",
                                            Parameters.REJECT_INVALID, blockHash);
        }
        //
        // Verify the transactions in the block
        //
        for (Transaction tx : transactions) {
            //
            // Verify the transaction structure
            //
            tx.verify(false);
            //
            // A transaction is locked if the lock time is greater than the block time (we allow
            // a 10-minute leeway)
            //
            if (tx.getLockTime() > timeStamp + (10*60)) {
                //
                // A transaction is unlocked if all of the input sequences are 0xffffffff even though
                // the lock time has not been reached
                //
                List<TransactionInput> txInputs = tx.getInputs();
                for (TransactionInput txInput : txInputs) {
                    if (txInput.getSeqNumber() != 0xffffffffL) {
                        log.error(String.format("Transaction lock time greater than block time\n"+
                                        "  Tx time %,d, Block time %,d\n  Block %s\n  Tx %s",
                                        tx.getLockTime(), timeStamp,
                                        blockHash.toString(), tx.getHashAsString()));
                        throw new VerificationException("Transaction lock time greater than block time",
                                                        Parameters.REJECT_INVALID, tx.getHash());
                    }
                }
            }
        }
    }

    /**
     * Determines if this block is equal to another block
     *
     * @param       obj             The block to compare
     * @return                      TRUE if the blocks are equal
     */
    @Override
    public boolean equals(Object obj) {
        boolean areEqual = false;
        if (obj != null && (obj instanceof Block))
            areEqual = blockHash.equals(((Block)obj).blockHash);
        return areEqual;
    }

    /**
     * Returns the hash code for this object.  The returned value is based on the block hash but is
     * not the same value.
     *
     * @return                      Hash code
     */
    @Override
    public int hashCode() {
        return blockHash.hashCode();
    }

    /**
     * Returns a string representation for this block
     *
     * @return                      Formatted string
     */
    @Override
    public String toString() {
        return String.format("Block hash: %s\n  Previous block hash %s\n  Merkle root: %s\n  Target difficulty %d",
                             getHashAsString(), getPrevBlockHash().toString(), getMerkleRoot().toString(),
                             targetDifficulty);
    }
}
