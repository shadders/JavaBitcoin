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

import java.math.BigInteger;

import java.net.InetAddress;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import java.util.concurrent.LinkedBlockingQueue;

/**
 * Global parameters for JavaBitcoin
 */
public class Parameters {

    /** Protocol version */
    public static final int PROTOCOL_VERSION = 70002;

    /** Minimum acceptable protocol version */
    public static final int MIN_PROTOCOL_VERSION = 60000;

    /** Services */
    public static final long NODE_NETWORK = 1;

    /** Our supported services */
    public static final long SUPPORTED_SERVICES = NODE_NETWORK;

    /** Default network port */
    public static final int DEFAULT_PORT = 8333;

    /** Software identifier */
    public static final String SOFTWARE_NAME = "/JavaBitcoin:1.1/";

    /** Production network magic number */
    public static final long MAGIC_NUMBER_PRODNET = 0xd9b4bef9L;

    /** Test network (RegTest) magic number */
    public static final long MAGIC_NUMBER_TESTNET = 0xdab5bffaL;

    /** Magic number */
    public static long MAGIC_NUMBER;

    /** Production network maximum target difficulty */
    public static final long MAX_DIFFICULTY_PRODNET = 0x1d00ffffL;

    /** Test network maximum target difficulty */
    public static final long MAX_DIFFICULTY_TESTNET = 0x207fffffL;

    /** Maximum target difficulty (represents least amount of work) */
    public static long MAX_TARGET_DIFFICULTY;

    /** Proof-of-work limit */
    public static BigInteger PROOF_OF_WORK_LIMIT;

    /** Production network genesis block */
    public static final String GENESIS_BLOCK_PRODNET =
                    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

    /** Test network genesis block */
    public static final String GENESIS_BLOCK_TESTNET =
                    "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";

    /** Genesis block hash */
    public static String GENESIS_BLOCK_HASH;

    /** Genesis block bytes */
    public static byte[] GENESIS_BLOCK_BYTES;

    /** Maximum block size */
    public static final int MAX_BLOCK_SIZE = 1*1024*1024;

    /** Maximum message size */
    public static final int MAX_MESSAGE_SIZE = 2*1024*1024;

    /** Maximum clock drift in seconds */
    public static final long ALLOWED_TIME_DRIFT = 2 * 60 * 60;

    /** Maximum amount of money in the Bitcoin system */
    public static final BigInteger MAX_MONEY = new BigInteger("21000000", 10).multiply(Utils.COIN);

    /** Dust transaction value */
    public static final BigInteger DUST_TRANSACTION = new BigInteger("5460", 10);

    /** Minimum transaction relay fee */
    public static final BigInteger MIN_TX_RELAY_FEE = new BigInteger("1000", 10);

    /** Maximum free transaction size */
    public static final int MAX_FREE_TX_SIZE = 10000;

    /** Maximum ban score before a peer is disconnected */
    public static final int MAX_BAN_SCORE = 100;

    /** Inventory vector types */
    public static final int INV_ERROR = 0;
    public static final int INV_TX = 1;
    public static final int INV_BLOCK = 2;
    public static final int INV_FILTERED_BLOCK = 3;

    /** Rejection reason codes */
    public static final int REJECT_MALFORMED = 0x01;
    public static final int REJECT_INVALID = 0x10;
    public static final int REJECT_OBSOLETE = 0x11;
    public static final int REJECT_DUPLICATE = 0x12;
    public static final int REJECT_NONSTANDARD = 0x40;
    public static final int REJECT_DUST = 0x41;
    public static final int REJECT_INSUFFICIENT_FEE = 0x42;
    public static final int REJECT_CHECKPOINT = 0x43;

    /** Block store */
    public static BlockStore blockStore;

    /** Block chain */
    public static BlockChain blockChain;

    /** Network listener */
    public static NetworkListener networkListener;

    /** External listen address */
    public static InetAddress listenAddress;

    /** Listen address status */
    public static boolean listenAddressValid;

    /** Listen port */
    public static int listenPort;

    /** Number of blocks received */
    public static long blocksReceived;

    /** Number of blocks sent */
    public static long blocksSent;

    /** Number of filtered blocks sent */
    public static long filteredBlocksSent;

    /** Number of transactions received */
    public static long txReceived;

    /** Number of transactions sent */
    public static long txSent;

    /** Number of transactions rejected */
    public static long txRejected;

    /** Network chain height */
    public static long networkChainHeight;

    /** List of peer requests that are waiting to be sent */
    public static final List<PeerRequest> pendingRequests = new LinkedList<>();

    /** List of peer requests that are waiting for a response */
    public static final List<PeerRequest> processedRequests = new LinkedList<>();

    /** List of transactions in the memory pool */
    public static final List<StoredTransaction> txPool = new LinkedList<>();

    /** Map of transactions in the memory pool: txHash -> tx */
    public static final Map<Sha256Hash, StoredTransaction> txMap = new HashMap<>(1000);

    /** List of recent transactions */
    public static final List<Sha256Hash> recentTxList = new LinkedList<>();

    /** Map of recent transactions: txHash -> txHash */
    public static final Map<Sha256Hash, Sha256Hash> recentTxMap = new HashMap<>(1000);

    /** List of orphan transactions */
    public static final List<StoredTransaction> orphanTxList = new LinkedList<>();

    /** Map of orphan transactions: parentTxHash -> orphanTxList */
    public static final Map<Sha256Hash, List<StoredTransaction>> orphanTxMap = new HashMap<>(250);

    /** List of recent spent outputs */
    public static final List<OutPoint> spentOutputsList = new LinkedList<>();

    /** Map of recent spent outputs: Outpoint -> spendingTxHash */
    public static final Map<OutPoint, Sha256Hash> spentOutputsMap = new HashMap<>(1000);

    /** List of Bloom filters */
    public static final List<BloomFilter> bloomFilters = new LinkedList<>();

    /** Database handler message queue */
    public static final LinkedBlockingQueue<Block> databaseQueue = new LinkedBlockingQueue<>();

    /** Message handler message queue */
    public static final LinkedBlockingQueue<Message> messageQueue = new LinkedBlockingQueue<>();

    /** Peer addresses */
    public static final List<PeerAddress> peerAddresses = new LinkedList<>();

    /** Peer address map */
    public static final Map<PeerAddress, PeerAddress> peerMap = new HashMap<>(250);

    /** Completed messages */
    public static final List<Message> completedMessages = new LinkedList<>();

    /** Short-term lock object */
    public static final Object lock = new Object();
}
