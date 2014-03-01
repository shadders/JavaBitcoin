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

import java.util.LinkedList;
import java.util.List;

/**
 * <p>An 'addr' message is sent to inform a nodes about peers on the network.</p>
 *
 * <p>Address Message</p>
 * <pre>
 *   Size       Field           Description
 *   ====       =====           ===========
 *   VarInt     Count           The number of addresses
 *   Variable   Addresses       One or more network addresses
 * </pre>
 *
 * <p>Network Address</p>
 * <pre>
 *   Size       Field           Description
 *   ====       =====           ===========
 *   4 bytes    Time            Timestamp in seconds since the epoch
 *   8 bytes    Services        Services provided by the node
 *  16 bytes    Address         IPv6 address (IPv4 addresses are encoded as IPv6 addresses)
 *   2 bytes    Port            Port (network byte order)
 * </pre>
 */
public class AddressMessage {

    /**
     * Build an 'addr' message
     *
     * We will include all peers that we have seen within the last hour as well as
     * our own external address
     *
     * @param       peer            The destination peer or null for a broadcast message
     * @return                      Message to be sent to the peer
     */
    public static Message buildAddressMessage(Peer peer) {
        //
        // Create an address list containing peers that we have seen within the past 15 minutes.
        // The maximum length of the list is 100 entries.  Static addresses are not included
        // in the list.  We will include our own address with a current timestamp if the
        // address is valid.
        //
        long oldestTime = System.currentTimeMillis()/1000 - (15*60);
        List<PeerAddress> addresses = new LinkedList<>();
        if (Parameters.listenAddressValid) {
            PeerAddress localAddress = new PeerAddress(Parameters.listenAddress, Parameters.listenPort);
            localAddress.setServices(Parameters.SUPPORTED_SERVICES);
            addresses.add(localAddress);
        }
        synchronized(Parameters.lock) {
            for (PeerAddress address : Parameters.peerAddresses) {
                if (addresses.size() == 100)
                    break;
                if (address.getTimeStamp() >= oldestTime && !address.isStatic())
                    addresses.add(address);
            }
        }
        //
        // Build the message payload
        //
        byte[] varCount = VarInt.encode(addresses.size());
        byte[] msgData = new byte[addresses.size()*PeerAddress.PEER_ADDRESS_SIZE+varCount.length];
        System.arraycopy(varCount, 0, msgData, 0, varCount.length);
        int offset = varCount.length;
        for (PeerAddress address : addresses) {
            address.getBytes(msgData, offset);
            offset += PeerAddress.PEER_ADDRESS_SIZE;
        }
        //
        // Build the message
        //
        ByteBuffer buffer = MessageHeader.buildMessage("addr", msgData);
        return new Message(buffer, peer, MessageHeader.ADDR_CMD);
    }

    /**
     * Process an 'addr' message and add new address to our peer address list
     *
     * @param       msg                     Message
     * @param       inStream                Message data stream
     * @throws      EOFException            Serialized byte stream is too short
     * @throws      IOException             Error reading from input stream
     * @throws      VerificationException   Message contains more than 1000 entries
     */
    public static void processAddressMessage(Message msg, ByteArrayInputStream inStream)
                                    throws EOFException, IOException, VerificationException {
        long oldestTime = System.currentTimeMillis()/1000 - (30*60);
        //
        // Get the address count
        //
        int addrCount = new VarInt(inStream).toInt();
        if (addrCount < 0 || addrCount > 1000)
            throw new VerificationException("More than 1000 addresses in 'addr' message");
        //
        // Process the addresses and keep any addresses that are not too old
        //
        for (int i=0; i<addrCount; i++) {
            PeerAddress peerAddress = new PeerAddress(inStream);
            if (peerAddress.getTimeStamp() < oldestTime ||
                                    (peerAddress.getServices()&Parameters.NODE_NETWORK) == 0 ||
                                    peerAddress.getAddress().equals(Parameters.listenAddress))
                continue;
            synchronized(Parameters.lock) {
                PeerAddress mapAddress = Parameters.peerMap.get(peerAddress);
                if (mapAddress == null) {
                    Parameters.peerAddresses.add(0, peerAddress);
                    Parameters.peerMap.put(peerAddress, peerAddress);
                } else {
                    mapAddress.setTimeStamp(Math.max(mapAddress.getTimeStamp(), peerAddress.getTimeStamp()));
                    mapAddress.setServices(peerAddress.getServices());
                }
            }
        }
    }
}
