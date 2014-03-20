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

import java.io.ByteArrayInputStream;
import java.io.IOException;

import java.nio.ByteBuffer;

import java.util.ArrayList;
import java.util.List;

/**
 * A message handler processes incoming messages on a separate dispatching thread.
 * It creates a response message if needed and then calls the network listener to
 * process the message completion.
 *
 * The message handler continues running until its shutdown() method is called.  It
 * receives messages from the messageQueue list, blocking if necessary until a message
 * is available.
 */
public class MessageHandler implements Runnable {

    /** Logger instance */
    private static final Logger log = LoggerFactory.getLogger(MessageHandler.class);

    /** Message handler thread */
    private Thread handlerThread;

    /** Message handler shutdown */
    private boolean handlerShutdown = false;

    /**
     * Creates a message handler
     */
    public MessageHandler() {
    }

    /**
     * Shuts down the message handler
     */
    public void shutdown() {
        handlerShutdown = true;
        handlerThread.interrupt();
    }

    /**
     * Processes messages and returns responses
     */
    @Override
    public void run() {
        log.info("Message handler started");
        handlerThread = Thread.currentThread();
        //
        // Process messages until we are shutdown
        //
        try {
            while (!handlerShutdown) {
                Message msg = Parameters.messageQueue.take();
                processMessage(msg);
            }
        } catch (InterruptedException exc) {
            if (!handlerShutdown)
                log.warn("Message handler interrupted", exc);
        } catch (Throwable exc) {
            log.error("Runtime exception while processing messages", exc);
        }
        //
        // Stopping
        //
        log.info("Message handler stopped");
    }

    /**
     * Process a message and return a response
     *
     * @param       msg             Message
     */
    private void processMessage(Message msg) throws InterruptedException {
        Peer peer = msg.getPeer();
        PeerAddress address = peer.getAddress();
        String cmd = "N/A";
        int cmdOp = 0;
        int reasonCode = 0;
        try {
            ByteBuffer msgBuffer = msg.getBuffer();
            byte[] msgBytes = msgBuffer.array();
            ByteArrayInputStream inStream = new ByteArrayInputStream(msgBytes);
            msg.setBuffer(null);
            //
            // Process the message header and get the command name
            //
            cmd = MessageHeader.processMessage(inStream, msgBytes);
            Integer cmdLookup = MessageHeader.cmdMap.get(cmd);
            if (cmdLookup != null)
                cmdOp = cmdLookup.intValue();
            msg.setCommand(cmdOp);
            //
            // Close the connection if the peer starts sending messages before the
            // handshake has been completed
            //
            if (peer.getVersionCount() < 2 && cmdOp != MessageHeader.VERSION_CMD &&
                                              cmdOp != MessageHeader.VERACK_CMD) {
                peer.setBanScore(Parameters.MAX_BAN_SCORE);
                throw new VerificationException("Non-version message before handshake completed",
                                                Parameters.REJECT_INVALID);
            }
            //
            // Process the message
            //
            switch (cmdOp) {
                case MessageHeader.VERSION_CMD:
                    //
                    // Process the 'version' message and generate the 'verack' response
                    //
                    VersionMessage.processVersionMessage(msg, inStream);
                    VersionAckMessage.buildVersionResponse(msg);
                    peer.incVersionCount();
                    address.setServices(peer.getServices());
                    log.info(String.format("Peer %s: Protocol level %d, Services %d, Agent %s, Height %d, "+
                                           "Relay blocks %s, Relay tx %s",
                             address.toString(), peer.getVersion(), peer.getServices(),
                             peer.getUserAgent(), peer.getHeight(),
                             peer.shouldRelayBlocks()?"Yes":"No",
                             peer.shouldRelayTx()?"Yes":"No"));
                    break;
                case MessageHeader.VERACK_CMD:
                    //
                    // Process the 'verack' message
                    //
                    peer.incVersionCount();
                    break;
                case MessageHeader.ADDR_CMD:
                    //
                    // Process the 'addr' message
                    //
                    AddressMessage.processAddressMessage(msg, inStream);
                    break;
                case MessageHeader.INV_CMD:
                    //
                    // Process the 'inv' message
                    //
                    InventoryMessage.processInventoryMessage(msg, inStream);
                    break;
                case MessageHeader.BLOCK_CMD:
                    //
                    // Process the 'block' message
                    //
                    // Deserialize the block and add it to the database queue for
                    // processing by the database handler.  We will remove each transaction
                    // from the memory pool and add it to the recent transaction list.
                    //
                    Block block = new Block(msgBytes, MessageHeader.HEADER_LENGTH,
                                            msgBytes.length-MessageHeader.HEADER_LENGTH, true);
                    List<Transaction> txList = block.getTransactions();
                    synchronized(Parameters.lock) {
                        for (Transaction tx : txList) {
                            Sha256Hash txHash = tx.getHash();
                            StoredTransaction storedTx = Parameters.txMap.get(txHash);
                            if (storedTx != null) {
                                Parameters.txPool.remove(storedTx);
                                Parameters.txMap.remove(txHash);
                            }
                            if (Parameters.recentTxMap.get(txHash) == null) {
                                Parameters.recentTxList.add(txHash);
                                Parameters.recentTxMap.put(txHash, txHash);
                            }
                        }
                        Parameters.databaseQueue.put(block);
                        Parameters.blocksReceived++;
                    }
                    break;
                case MessageHeader.TX_CMD:
                    //
                    // Process the 'tx' message
                    //
                    TransactionMessage.processTransactionMessage(msg, inStream);
                    break;
                case MessageHeader.GETADDR_CMD:
                    //
                    // Process the 'getaddr' message
                    //
                    Message addrMsg = AddressMessage.buildAddressMessage(peer);
                    msg.setBuffer(addrMsg.getBuffer());
                    msg.setCommand(addrMsg.getCommand());
                    break;
                case MessageHeader.GETDATA_CMD:
                    //
                    // Process the 'getdata' message
                    //
                    GetDataMessage.processGetDataMessage(msg, inStream);
                    //
                    // The 'getdata' command sends data in batches, so we need
                    // to check if it needs to be restarted.  If it does, we will
                    // reset the message buffer so that it will be processed again
                    // when the request is restarted.
                    //
                    if (msg.getRestartIndex() != 0) {
                        msgBuffer.rewind();
                        msg.setRestartBuffer(msgBuffer);
                        synchronized(Parameters.lock) {
                            peer.getDeferredList().add(msg);
                        }
                    }
                    //
                    // Send an 'inv' message for the current chain head to restart
                    // the peer download if the previous 'getblocks' was incomplete.
                    //
                    if (peer.isIncomplete() && msg.getBuffer() == null) {
                        peer.setIncomplete(false);
                        Sha256Hash chainHead = Parameters.blockStore.getChainHead();
                        List<Sha256Hash> blockList = new ArrayList<>(1);
                        blockList.add(chainHead);
                        Message invMessage = InventoryMessage.buildInventoryMessage(peer,
                                                            Parameters.INV_BLOCK, blockList);
                        msg.setBuffer(invMessage.getBuffer());
                        msg.setCommand(invMessage.getCommand());
                    }
                    break;
                case MessageHeader.GETBLOCKS_CMD:
                    //
                    // Process the 'getblocks' message
                    //
                    GetBlocksMessage.processGetBlocksMessage(msg, inStream);
                    break;
                case MessageHeader.NOTFOUND_CMD:
                    //
                    // Process the 'notfound' message
                    //
                    NotFoundMessage.processNotFoundMessage(msg, inStream);
                    break;
                case MessageHeader.PING_CMD:
                    //
                    // Process the 'ping' message
                    //
                    PingMessage.processPingMessage(msg, inStream);
                    break;
                case MessageHeader.PONG_CMD:
                    //
                    // Process the 'pong' message
                    //
                    peer.setPing(false);
                    log.info(String.format("'pong' response received from %s", address.toString()));
                    break;
                case MessageHeader.GETHEADERS_CMD:
                    //
                    // Process the 'getheaders' message
                    //
                    GetHeadersMessage.processGetHeadersMessage(msg, inStream);
                    break;
                case MessageHeader.MEMPOOL_CMD:
                    //
                    // Process the 'mempool' message
                    //
                    MempoolMessage.processMempoolMessage(msg, inStream);
                    break;
                case MessageHeader.FILTERLOAD_CMD:
                    //
                    // Process the 'filterload' cmd
                    //
                    FilterLoadMessage.processFilterLoadMessage(msg, inStream);
                    log.info(String.format("Bloom filter loaded for peer %s", address.toString()));
                    break;
                case MessageHeader.FILTERADD_CMD:
                    //
                    // Process the 'filteradd' command
                    //
                    FilterAddMessage.processFilterAddMessage(msg, inStream);
                    log.info(String.format("Bloom filter added for peer %s", address.toString()));
                    break;
                case MessageHeader.FILTERCLEAR_CMD:
                    //
                    // Process the 'filterclear' command
                    //
                    BloomFilter filter = peer.getBloomFilter();
                    peer.setBloomFilter(null);
                    if (filter != null) {
                        synchronized(Parameters.lock) {
                            Parameters.bloomFilters.remove(filter);
                        }
                    }
                    log.info(String.format("Bloom filter cleared for peer %s", address.toString()));
                    break;
                case MessageHeader.REJECT_CMD:
                    //
                    // Process the 'reject' command
                    //
                    RejectMessage.processRejectMessage(msg, inStream);
                    break;
                case MessageHeader.ALERT_CMD:
                    //
                    // Process the 'alert' command
                    //
                    AlertMessage.processAlertMessage(msg, inStream);
                    break;
                default:
                    log.error(String.format("Unrecognized '%s' message from %s", cmd, address.toString()));
                    Main.dumpData("Unrecognized Message", msgBytes, Math.min(msgBytes.length, 80));
            }
        } catch (IOException exc) {
            log.error(String.format("I/O error while processing '%s' message from %s",
                                    cmd, address.toString()), exc);
            reasonCode = Parameters.REJECT_MALFORMED;
            if (cmdOp == MessageHeader.TX_CMD)
                Parameters.txRejected++;
            else if (cmdOp == MessageHeader.VERSION_CMD)
                peer.setDisconnect(true);
            if (peer.getVersion() >= 70002) {
                Message rejectMsg = RejectMessage.buildRejectMessage(peer, cmd, reasonCode, exc.getMessage());
                msg.setBuffer(rejectMsg.getBuffer());
                msg.setCommand(rejectMsg.getCommand());
            }
        } catch (VerificationException exc) {
            log.error(String.format("Message verification failed for '%s' message from %s\n  %s\n  %s",
                                    cmd, address.toString(), exc.getMessage(), exc.getHash().toString()));
            reasonCode = exc.getReason();
            if (cmdOp == MessageHeader.TX_CMD)
                Parameters.txRejected++;
            else if (cmdOp == MessageHeader.VERSION_CMD)
                peer.setDisconnect(true);
            if (peer.getVersion() >= 70002) {
                Message rejectMsg = RejectMessage.buildRejectMessage(peer, cmd, reasonCode,
                                                                     exc.getMessage(), exc.getHash());
                msg.setBuffer(rejectMsg.getBuffer());
                msg.setCommand(rejectMsg.getCommand());
            }
        }
        //
        // Add the message to the completed message list and wakeup the network listener.  We will
        // bump the banscore for the peer if the message was rejected because it was malformed
        // or invalid.
        //
        synchronized(Parameters.lock) {
            Parameters.completedMessages.add(msg);
            if (reasonCode != 0) {
                if (reasonCode == Parameters.REJECT_MALFORMED || reasonCode == Parameters.REJECT_INVALID) {
                    int banScore = peer.getBanScore() + 5;
                    peer.setBanScore(banScore);
                    if (banScore >= Parameters.MAX_BAN_SCORE)
                        peer.setDisconnect(true);
                }
            }
        }
        Parameters.networkListener.wakeup();
    }
}
