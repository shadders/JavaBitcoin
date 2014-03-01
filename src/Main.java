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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import java.net.InetAddress;
import java.net.UnknownHostException;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.LogManager;
import java.util.Properties;

import javax.swing.*;

/**
 * <p>Main class for the JavaBitcoin peer node</p>
 *
 * <p>The JavaBitcoin peer node accepts blocks from the network, verifies them and then stores them in its
 * database.  It will also relay blocks and transactions to other nodes on the network.</p>
 *
 * <p>If no command-line arguments are provided, we will connect to the production Bitcoin network
 * using DNS discovery.  The production database will be used.</p>
 * <p>The following command-line arguments are supported:</p>
 * <table>
 * <col width=30%/>
 * <col width=70%/>
 * <tr><td>LOAD PROD|TEST directory-path start-block</td>
 * <td>Load the block chain from the reference client data directory and create the block database.  Specify PROD
 * to load the production database or TEST to load the test database.  The
 * default reference client data directory will be used if no directory path is specified.  The program will
 * terminate after loading the block chain.</td></tr>
 *
 * <tr><td>PROD peer1 peer2 ...</td>
 * <td>Start the program using the production network.  Application files are stored in the application data
 * directory and the production database is used.
 * DNS discovery will be used if no peer nodes are specified.</td></tr>
 *
 * <tr><td>RETRY PROD|TEST block-hash</td>
 * <td>Retry a block which is currently held.  Specify PROD to use the production database or TEST to use the
 * test database.  The block hash is the 64-character hash for the block to be retried.</td></tr>
 *
 * <tr><td>TEST peer1 peer2 ...</td>
 * <td>Start the program using the regression test network.  Application files are stored in the TestNet
 * folder in the application data directory and the test database is used.  At least one peer node must
 * be specified since DNS discovery is not supported for the regression test network.</td></tr>
 * </table>
 *
 * <p>A peer is specified as address:port.  Specifying 'none' will result in no outbound connections and
 * the program will just listen for inbound connections.</p>
 *
 * <p>The following command-line options can be specified:</p>
 * <table>
 * <col width=30%/>
 * <col width=70%/>
 * <tr><td>-Dbitcoin.datadir=directory-path</td>
 * <td>Specifies the application data directory.  Application data will be stored in
 * ~/AppData/Roaming/JavaBitcoin if no path is specified.</td></tr>
 *
 * <tr><td>-Dbitcoin.verify.blocks=n</td>
 * <td>Blocks are normally verified as they are added to the block chain.  Block verification can be disabled
 * to improve performance. Specify 1 to enable verification and 0 to disable verification.
 * The default is 1.</td></tr>
 *
 * <tr><td>-Djava.util.logging.config.file=file-path</td>
 * <td>Specifies the logger configuration file.  The logger properties will be read from 'logging.properties'
 * in the application data directory.  If this file is not found, the 'java.util.logging.config.file' system
 * property will be used to locate the logger configuration file.  If this property is not defined,
 * the logger properties will be obtained from jre/lib/logging.properties.
 *      <ul>
 *      <li>JDK FINE corresponds to the SLF4J DEBUG level</li>
 *      <li>JDK INFO corresponds to the SLF4J INFO level</li>
 *      <li>JDK WARNING corresponds to the SLF4J WARN level</li>
 *      <li>JDK SEVERE corresponds to the SLF4J ERROR level</li>
 *      </ul>
 *  </td></tr>
 * </table>
 *
 * <p>The following properties can be specified in javabitcoin.properties:</p>
 * <table>
 * <col width=30%/>
 * <col width=70%/>
 * <tr><td>maxconnections=n</td>
 * <td>Specifies the maximum number of inbound and outbound connections and defaults to 32.</td></tr>
 *
 * <tr><td>maxoutbound=n</td>
 * <td>Specifies the maximum number of outbound connections and defaults to 8.</td></tr>
 *
 * <tr><td>port=n</td>
 * <td>Specifies the port for receiving inbound connections and defaults to 8333</td></tr>
 *
 * <tr><td>dbtype=type</td>
 * <td>Specify 'leveldb' to use LevelDB for the database or 'postgresql' to use PostgreSQL.
 * The LevelDB database will be used if no value is specified.</td></tr>
 *
 * <tr><td>dbuser=userid</td>
 * <td>Specifies the SQL database user</td></tr>
 *
 * <tr><td>dbpw=password</td>
 * <td>Specifies the SQL database password</td></tr>
 *
 * <tr><td>dbport=n</td>
 * <td>Specifies the SQL database TCP/IP port</td></tr>
 * </table>
 */
public class Main {

    /** Logger instance */
    private static final Logger log = LoggerFactory.getLogger(Main.class);

    /** Default maximum connections */
    private static final String MAX_CONNECTIONS = "32";

    /** Default maximum outbound connections */
    private static final String MAX_OUTBOUND = "8";

    /** Default database user */
    private static final String DB_USER = "javabtc";

    /** Default database password */
    private static final String DB_PASSWORD = "btcnode";

    /** Default database port */
    private static final String DB_PORT = "5432";

    /** Application properties */
    public static Properties properties;

    /** Main application window */
    public static MainWindow mainWindow;

    /** Data directory */
    private static String dataPath;

    /** Application properties file */
    private static File propFile;

    /** Peer addresses file */
    private static File peersFile;

    /** Test network */
    private static boolean testNetwork = false;

    /** Load block chain */
    private static boolean loadBlockChain = false;

    /** Retry block */
    private static boolean retryBlock = false;

    /** Bypass block verification */
    private static boolean verifyBlocks = true;

    /** Block chain data directory for load */
    private static String blockChainPath;

    /** Starting block number for load */
    private static int startBlock;

    /** Retry block hash */
    private static Sha256Hash retryHash;

    /** Peer address */
    private static PeerAddress[] peerAddresses;

    /** Block store */
    private static BlockStore blockStore;

    /** Block chain */
    private static BlockChain blockChain;

    /** Thread group */
    private static ThreadGroup threadGroup;

    /** Worker threads */
    private static List<Thread> threads = new ArrayList<>(5);

    /** Database listener */
    private static DatabaseHandler databaseHandler;

    /** Message handlers */
    private static MessageHandler messageHandler;

    /** Deferred exception text */
    private static String deferredText;

    /** Deferred exception */
    private static Throwable deferredException;

    /**
     * The main() method is invoked by the JVM to start the application
     *
     * @param       args            Command-line arguments
     */
    public static void main(String[] args) {
        try {
            //
            // Process command-line options
            //
            dataPath = System.getProperty("bitcoin.datadir");
            if (dataPath == null)
                dataPath = System.getProperty("user.home")+"\\AppData\\Roaming\\JavaBitcoin";
            String pString = System.getProperty("bitcoin.verify.blocks");
            if (pString != null && pString.equals("0"))
                verifyBlocks = false;
            //
            // Process command-line arguments
            //
            if (args.length != 0)
                processArguments(args);
            //
            // Initialize the network parameters (production or test)
            //
            String genesisName;
            if (testNetwork) {
                dataPath = dataPath+"\\TestNet";
                Parameters.MAGIC_NUMBER = Parameters.MAGIC_NUMBER_TESTNET;
                Parameters.MAX_TARGET_DIFFICULTY = Parameters.MAX_DIFFICULTY_TESTNET;
                Parameters.GENESIS_BLOCK_HASH = Parameters.GENESIS_BLOCK_TESTNET;
                genesisName = "GenesisBlock/GenesisBlockTest.dat";
            } else {
                Parameters.MAGIC_NUMBER = Parameters.MAGIC_NUMBER_PRODNET;
                Parameters.MAX_TARGET_DIFFICULTY = Parameters.MAX_DIFFICULTY_PRODNET;
                Parameters.GENESIS_BLOCK_HASH = Parameters.GENESIS_BLOCK_PRODNET;
                genesisName = "GenesisBlock/GenesisBlockProd.dat";
            }
            Parameters.PROOF_OF_WORK_LIMIT = Utils.decodeCompactBits(Parameters.MAX_TARGET_DIFFICULTY);
            //
            // Load the genesis block
            //
            Class<?> mainClass = Class.forName("JavaBitcoin.Main");
            InputStream classStream = mainClass.getClassLoader().getResourceAsStream(genesisName);
            if (classStream == null)
                throw new IllegalStateException("Genesis block resource not found");
            Parameters.GENESIS_BLOCK_BYTES = new byte[classStream.available()];
            classStream.read(Parameters.GENESIS_BLOCK_BYTES);
            //
            // Create the data directory if it doesn't exist
            //
            File dirFile = new File(dataPath);
            if (!dirFile.exists())
                dirFile.mkdirs();
            //
            // Initialize the logging properties from 'logging.properties'
            //
            File logFile = new File(dataPath+"\\logging.properties");
            if (logFile.exists()) {
                FileInputStream inStream = new FileInputStream(logFile);
                LogManager.getLogManager().readConfiguration(inStream);
            }
            //
            // Use the brief logging format
            //
            BriefLogFormatter.init();
            log.info(String.format("Application data path: '%s'", dataPath));
            log.info(String.format("Block verification is %s", (verifyBlocks?"enabled":"disabled")));
            //
            // Load the saved application properties
            //
            propFile = new File(dataPath+"\\JavaBitcoin.properties");
            properties = new Properties();
            if (propFile.exists()) {
                try (FileInputStream in = new FileInputStream(propFile)) {
                    properties.load(in);
                }
            } else {
                properties.setProperty("maxconnections", MAX_CONNECTIONS);
                properties.setProperty("maxoutbound", MAX_OUTBOUND);
                properties.setProperty("port", String.valueOf(Parameters.DEFAULT_PORT));
                properties.setProperty("dbtype", "leveldb");
                properties.setProperty("dbuser", DB_USER);
                properties.setProperty("dbpw", DB_PASSWORD);
                properties.setProperty("dbport", DB_PORT);
                saveProperties();
            }
            //
            // Create the block store
            //
            String dbtype = properties.getProperty("dbtype", "leveldb");
            switch (dbtype) {
                case "postgresql":
                    blockStore = new BlockStorePg(dataPath, testNetwork?"jtestdb":"javadb",
                                    properties.getProperty("dbuser", DB_USER),
                                    properties.getProperty("dbpw", DB_PASSWORD),
                                    Integer.parseInt(properties.getProperty("dbport", DB_PORT)));
                    break;
                case "leveldb":
                    blockStore = new BlockStoreLdb(dataPath);
                    break;
                default:
                    throw new IllegalArgumentException(String.format("Unrecognized database type '%s", dbtype));
            }
            Parameters.blockStore = blockStore;
            //
            // Create the block chain
            //
            blockChain = new BlockChain(verifyBlocks);
            Parameters.blockChain = blockChain;
            //
            // Load the block chain from disk and then exit.
            //
            if (loadBlockChain) {
                loadBlockChain();
                blockStore.close();
                System.exit(0);
            }
            //
            // Retry a held block and then exit
            //
            if (retryBlock) {
                StoredBlock storedBlock = blockStore.getStoredBlock(retryHash);
                if (storedBlock != null) {
                    if (!storedBlock.isOnChain()) {
                        blockChain.updateBlockChain(storedBlock);
                    } else {
                        log.error(String.format("Block is already on the chain\n  %s",
                                                retryHash.toString()));
                    }
                } else{
                    log.error(String.format("Block not found\n  %s", retryHash.toString()));
                }
                blockStore.close();
                System.exit(0);
            }
            //
            // Clean up the database by removing old entries
            //
            blockStore.cleanupDatabase(false);
            //
            // Get the peer addresses
            //
            peersFile = new File(String.format("%s\\peers.dat", dataPath));
            if (peersFile.exists()) {
                int peerCount = (int)peersFile.length()/PeerAddress.PEER_ADDRESS_SIZE;
                try (FileInputStream inStream = new FileInputStream(peersFile)) {
                    for (int i=0; i<peerCount; i++) {
                        PeerAddress peerAddress = new PeerAddress(inStream);
                        Parameters.peerAddresses.add(peerAddress);
                        Parameters.peerMap.put(peerAddress, peerAddress);
                    }
                }
            }
            //
            // Start the worker threads
            //
            threadGroup = new ThreadGroup("Workers");

            databaseHandler = new DatabaseHandler();
            Thread thread = new Thread(threadGroup, databaseHandler);
            thread.start();
            threads.add(thread);

            Parameters.networkListener = new NetworkListener(
                        Integer.parseInt(properties.getProperty("maxconnections", MAX_CONNECTIONS)),
                        Integer.parseInt(properties.getProperty("maxoutbound", MAX_OUTBOUND)),
                        Integer.parseInt(properties.getProperty("port", String.valueOf(Parameters.DEFAULT_PORT))),
                        peerAddresses);
            thread = new Thread(threadGroup, Parameters.networkListener);
            thread.start();
            threads.add(thread);

            messageHandler = new MessageHandler();
            thread = new Thread(threadGroup, messageHandler);
            thread.start();
            threads.add(thread);
            //
            // Start the GUI
            //
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            javax.swing.SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    createAndShowGUI();
                }
            });
        } catch (Exception exc) {
            log.error("Exception during program initialization", exc);
        }
    }

    /**
     * Save the application properties
     */
    public static void saveProperties() {
        try {
            try (FileOutputStream out = new FileOutputStream(propFile)) {
                properties.store(out, "JavaBitcoin Properties");
            }
        } catch (Exception exc) {
            Main.logException("Exception while saving application properties", exc);
        }
    }

    /**
     * Create and show our application GUI
     *
     * This method is invoked on the AWT event thread to avoid timing
     * problems with other window events
     */
    private static void createAndShowGUI() {
        try {
            //
            // Use the normal window decorations as defined by the look-and-feel
            // schema
            //
            JFrame.setDefaultLookAndFeelDecorated(true);
            //
            // Create the main application window
            //
            mainWindow = new MainWindow();
            //
            // Show the application window
            //
            mainWindow.pack();
            mainWindow.setVisible(true);
        } catch (Exception exc) {
            Main.logException("Exception while initializing application window", exc);
        }
    }

    /**
     * Shutdown and exit
     */
    public static void shutdown() {
        //
        // Stop the network
        //
        Parameters.networkListener.shutdown();
        databaseHandler.shutdown();
        messageHandler.shutdown();
        //
        // Wait for threads to terminate
        //
        try {
            log.info("Waiting for worker threads to stop");
            for (Thread thread : threads)
                thread.join(2*60*1000);
            log.info("Worker threads have stopped");
        } catch (InterruptedException exc) {
            log.info("Interrupted while waiting for threads to stop");
        }
        //
        // Close the database
        //
        blockStore.close();
        //
        // Save the first 50 peer addresses
        //
        try {
            try (FileOutputStream outStream = new FileOutputStream(peersFile)) {
                int peerCount = 0;
                for (PeerAddress peerAddress : Parameters.peerAddresses) {
                    if (!peerAddress.isStatic()) {
                        outStream.write(peerAddress.getBytes());
                        peerCount++;
                        if (peerCount >= 50)
                            break;
                    }
                }
            }
        } catch (IOException exc) {
            log.error("Unable to save peer addresses", exc);
        }
        //
        // Save the application properties
        //
        saveProperties();
        //
        // All done
        //
        System.exit(0);
    }

    /**
     * Load the block chain from the reference client data directory
     */
    private static void loadBlockChain() {
        int blockCount = 0;
        int heldCount = 0;
        long blockTime = 0;
        String fileName = null;
        boolean stopLoad = false;
        try {
            //
            // Get the block chain file list from the 'blocks' subdirectory sorted by ordinal value
            // (blk00000.dat, blk00001.dat, blk00002.dat, etc).  We will stop when we reach a
            // non-existent file.
            //
            List<File> fileList = new ArrayList<>(150);
            for (int i=startBlock; true; i++) {
                File file = new File(blockChainPath+String.format("\\blocks\\blk%05d.dat", i));
                if (!file.exists())
                    break;
                fileList.add(file);
            }
            //
            // Read the blocks in each file
            //
            // The blocks in the file are separated by 4 bytes containing the network-specific packet magic
            // value.  The next 4 bytes contain the block length in little-endian format.
            //
            byte[] numBuffer = new byte[8];
            byte[] blockBuffer = new byte[Parameters.MAX_BLOCK_SIZE];
            for (File inFile : fileList) {
                fileName = inFile.getName();
                log.info(String.format("Processing block data file %s", fileName));
                try (FileInputStream in = new FileInputStream(inFile)) {
                    while (!stopLoad) {
                        //
                        // Get the magic number and the block length from the input stream.
                        // Stop when we reach the end of the file or the magic number is zero.
                        //
                        int count = in.read(numBuffer);
                        if (count < 8)
                            break;
                        long magic = Utils.readUint32LE(numBuffer, 0);
                        long length = Utils.readUint32LE(numBuffer, 4);
                        if (magic == 0)
                            break;
                        if (magic != Parameters.MAGIC_NUMBER) {
                            log.error(String.format("Block magic number %X is incorrect", magic));
                            throw new IOException("Incorrect file format");
                        }
                        if (length > blockBuffer.length) {
                            log.error(String.format("Block length %d exceeds maximum block size", length));
                            throw new IOException("Incorrect file format");
                        }
                        //
                        // Read the block from the input stream
                        //
                        count = in.read(blockBuffer, 0, (int)length);
                        if (count != (int)length) {
                            log.error(String.format("Block truncated: Needed %d bytes, Read %d bytes",
                                      (int)length, count));
                            throw new IOException("Incorrect file format");
                        }
                        //
                        // Create a new block from the serialized byte stream.  Since we are
                        // reading from a trusted input source, we won't waste time verifying blocks
                        // (this also avoids a lot of problems with bad blocks that made it into
                        // the block chain before the rules were tightened)
                        //
                        Block block = new Block(blockBuffer, 0, count, false);
                        blockTime = block.getTimeStamp();
                        //
                        // Add the block to the block store and update the block chain.  Stop
                        // loading blocks if we get 5 consecutive blocks being held (something
                        // is wrong and needs to be investigated)
                        //
                        if (blockStore.isNewBlock(block.getHash())) {
                            if (blockChain.storeBlock(block) == null) {
                              log.info(String.format("Current block was not added to the block chain\n  %s",
                                                     block.getHashAsString()));
                              if (++heldCount >= 5)
                                stopLoad = true;
                            } else {
                                heldCount = 0;
                            }
                        }
                        blockCount++;
                    }
                }
                //
                // Clean up the database by removing expired entries
                //
                if (blockTime > 0)
                    blockStore.cleanupDatabase(true);
                //
                // Stop loading blocks if we encountered a problem
                //
                if (stopLoad)
                    break;
            }
            //
            // All done
            //
            log.info(String.format("Processed %d blocks", blockCount));
        } catch (IOException exc) {
            log.error(String.format("I/O error reading block chain file %s", fileName), exc);
        } catch (BlockStoreException exc) {
            log.error("Unable to store block in database", exc);
        } catch (VerificationException exc) {
            log.error("Block verification error", exc);
        } catch (Exception exc) {
            log.error("Exception during block chain load", exc);
        }
    }

    /**
     * Parses the command-line arguments
     *
     * @param       args            Command-line arguments
     */
    private static void processArguments(String[] args) throws UnknownHostException {
        //
        // PROD indicates we should use the production network
        // TEST indicates we should use the test network
        // LOAD indicates we should load the block chain from the reference client data directory
        // RETRY indicates we should retry a block that is currently held
        //
        if (args[0].equalsIgnoreCase("LOAD")) {
            loadBlockChain = true;
            if (args.length < 2)
                throw new IllegalArgumentException("Specify PROD or TEST with the LOAD option");

            if (args[1].equalsIgnoreCase("TEST")) {
                testNetwork = true;
            } else if (!args[1].equalsIgnoreCase("PROD")) {
                throw new IllegalArgumentException("Specify PROD or TEST after the LOAD option");
            }

            if (args.length > 2) {
                blockChainPath = args[2];
            } else {
                blockChainPath = System.getProperty("user.home")+"\\AppData\\Roaming\\Bitcoin";
            }

            if (args.length > 3) {
                startBlock = Integer.parseInt(args[3]);
            } else {
                startBlock = 0;
            }

            return;
        }
        if (args[0].equalsIgnoreCase("RETRY")) {
            retryBlock = true;
            if (args.length < 3)
                throw new IllegalArgumentException("Specify PROD or TEST followed by the block hash");

            if (args[1].equalsIgnoreCase("TEST")) {
                testNetwork = true;
            } else if (!args[1].equalsIgnoreCase("PROD")) {
                throw new IllegalArgumentException("Specify PROD or TEST after the RETRY option");
            }

            retryHash = new Sha256Hash(args[2]);
            return;
        }
        if (args[0].equalsIgnoreCase("TEST")) {
            testNetwork = true;
        } else if (!args[0].equalsIgnoreCase("PROD")) {
            throw new IllegalArgumentException("Valid options are LOAD, RETRY, PROD and TEST");
        }
        //
        // One or more peer nodes can be specified as addr:port (for example, 127.0.0.1:19000)
        // These nodes will be used instead of using DNS Discovery to find nodes.  Specify
        // 'none' to disable outbound connections and just listen for inbound connections.
        //
        int count = args.length - 1;
        if (count > 0) {
            if (args[1].equalsIgnoreCase("none")) {
                peerAddresses = new PeerAddress[0];
            } else {
                peerAddresses = new PeerAddress[count];
                for (int i=0; i<count; i++) {
                    String[] peerParts = args[i+1].split(":");
                    if (peerParts.length != 2)
                        throw new IllegalArgumentException("Incorrect address:port specification: "+args[i+1]);
                    String[] addrParts = peerParts[0].split("\\D");
                    if (addrParts.length != 4)
                        throw new IllegalArgumentException("Invalid IPv4 address specification: "+peerParts[0]);
                    byte[] peerAddr = new byte[4];
                    for (int j=0; j<4; j++)
                        peerAddr[j] = (byte)Integer.parseInt(addrParts[j]);
                    InetAddress address = InetAddress.getByAddress(peerAddr);
                    peerAddresses[i] = new PeerAddress(address, Integer.parseInt(peerParts[1]));
                }
            }
        }
        if (testNetwork && peerAddresses == null)
            throw new IllegalArgumentException("You must specify a peer or 'none' for the test network");
    }

    /**
     * Display a dialog when an exception occurs.
     *
     * @param       text        Text message describing the cause of the exception
     * @param       exc         The Java exception object
     */
    public static void logException(String text, Throwable exc) {
        if (SwingUtilities.isEventDispatchThread()) {
            StringBuilder string = new StringBuilder(512);
            //
            // Display our error message
            //
            string.append("<html><b>");
            string.append(text);
            string.append("</b><br><br>");
            //
            // Display the exception object
            //
            string.append(exc.toString());
            string.append("<br>");
            //
            // Display the stack trace
            //
            StackTraceElement[] trace = exc.getStackTrace();
            int count = 0;
            for (StackTraceElement elem : trace) {
                string.append(elem.toString());
                string.append("<br>");
                if (++count == 25)
                    break;
            }
            string.append("</html>");
            JOptionPane.showMessageDialog(Main.mainWindow, string, "Error", JOptionPane.ERROR_MESSAGE);
        } else if (deferredException == null) {
            deferredText = text;
            deferredException = exc;
            try {
                javax.swing.SwingUtilities.invokeAndWait(new Runnable() {
                    @Override
                    public void run() {
                        Main.logException(deferredText, deferredException);
                        deferredException = null;
                        deferredText = null;
                    }
                });
            } catch (Exception logexc) {
                log.error("Unable to log exception during program initialization");
            }
        }
    }

    /**
     * Dumps a byte array to the log
     *
     * @param       text        Text message
     * @param       data        Byte array
     */
    public static void dumpData(String text, byte[] data) {
        dumpData(text, data, 0, data.length);
    }

    /**
     * Dumps a byte array to the log
     *
     * @param       text        Text message
     * @param       data        Byte array
     * @param       length      Length to dump
     */
    public static void dumpData(String text, byte[] data, int length) {
        dumpData(text, data, 0, length);
    }

    /**
     * Dump a byte array to the log
     *
     * @param       text        Text message
     * @param       data        Byte array
     * @param       offset      Offset into array
     * @param       length      Data length
     */
    public static void dumpData(String text, byte[] data, int offset, int length) {
        StringBuilder outString = new StringBuilder(512);
        outString.append(text);
        outString.append("\n");
        for (int i=0; i<length; i++) {
            if (i%32 == 0)
                outString.append(String.format(" %14X  ", i));
            else if (i%4 == 0)
                outString.append(" ");
            outString.append(String.format("%02X", data[offset+i]));
            if (i%32 == 31)
                outString.append("\n");
        }
        if (length%32 != 0)
            outString.append("\n");
        log.info(outString.toString());
    }
}
