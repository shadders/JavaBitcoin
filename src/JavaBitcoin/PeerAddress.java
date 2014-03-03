/**
 * Copyright 2011 Google Inc.
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

import java.io.EOFException;
import java.io.InputStream;
import java.io.IOException;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

import java.util.Arrays;

/**
 * A PeerAddress holds an IP address and port number representing the network location of
 * a peer in the Bitcoin Peer-to-Peer network.
 */
public class PeerAddress {

    /** Length of an encoded peer address */
    public static final int PEER_ADDRESS_SIZE = 30;

    /** IPv6-encoded IPv4 address prefix */
    public static final byte[] IPV6_PREFIX = new byte[] {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0xff, (byte)0xff
    };

    /** The IP address */
    private InetAddress address;

    /** The IP port */
    private int port;

    /** Time seen */
    private long timeSeen;

    /** Peer services */
    private long services;

    /** Peer connected */
    private boolean connected;

    /** Outbound connection */
    private boolean outboundConnection;

    /** Static address */
    private boolean staticAddress;

    /**
     * Constructs a peer address from the given IP address and port
     *
     * @param       address         IP address
     * @param       port            IP port
     */
    public PeerAddress(InetAddress address, int port) {
        this.address = address;
        this.port = port;
        timeSeen = System.currentTimeMillis()/1000;
    }

    /**
     * Constructs a peer address from the given IP address and port
     *
     * @param       address         IP address
     * @param       port            IP port
     * @param       timeSeen        Latest time peer was seen
     */
    public PeerAddress(InetAddress address, int port, long timeSeen) {
        this.address = address;
        this.port = port;
        this.timeSeen = timeSeen;
    }

    /**
     * Constructs a peer address from a network socket
     *
     * @param       socket          Network socket
     */
    public PeerAddress(InetSocketAddress socket) {
        this(socket.getAddress(), socket.getPort());
    }

    /**
     * Constructs a peer address from a string in the format "[address]:port" where
     * address can be "nnn.nnn.nnn.nnn" for IPv4 or "xxxx:xxxx:xxxx;xxxx:xxxx:xxxx:xxxx:xxxx"
     * for IPv6.
     *
     * @param       peerString              Address string
     * @throws      UnknownHostException    Incorrect address format
     */
    public PeerAddress(String peerString) throws UnknownHostException {
        //
        // Separate the address and the port
        //
        int addrSep = peerString.lastIndexOf(']');
        int portSep = peerString.lastIndexOf(':');
        if (peerString.charAt(0) != '[' || addrSep < 0 ||
                                portSep < addrSep || portSep == peerString.length()-1)
                throw new UnknownHostException("Incorrect [address]:port format");
        String addrString = peerString.substring(1, addrSep);
        String portString = peerString.substring(portSep+1);
        //
        // Decode the address
        //
        byte[] addrBytes;
        if (addrString.indexOf('.') >= 0) {
            String[] addrParts = addrString.split("\\D");
            if (addrParts.length != 4)
                throw new UnknownHostException("Incorrect IPv4 address format");
            addrBytes = new byte[4];
            for (int j=0; j<4; j++)
                addrBytes[j] = (byte)Integer.parseInt(addrParts[j]);
        } else if (addrString.indexOf(':') >= 0) {
            String[] addrParts = addrString.split(":");
            if (addrParts.length != 8)
                throw new UnknownHostException("Incorrect IPv6 address format");
            addrBytes = new byte[16];
            int offset = 0;
            for (int j=0; j<8; j++) {
                if (addrParts[j].length() == 0) {
                    offset += 2;
                } else {
                    int nibble = Integer.parseInt(addrParts[j], 16);
                    addrBytes[offset++] = (byte)(nibble>>8);
                    addrBytes[offset++] = (byte)nibble;
                }
            }
        } else {
            throw new UnknownHostException("Incorrect [address]:port format");
        }
        //
        // Create the address and port values
        //
        address = InetAddress.getByAddress(addrBytes);
        port = Integer.parseInt(portString);
        timeSeen = System.currentTimeMillis()/1000;
    }

    /**
     * Constructs a peer address from the serialized data
     *
     * @param       inStream        Input stream
     * @throws      EOFException    End-of-data while processing serialized data
     * @throws      IOException     Unable to read input stream
     */
    public PeerAddress(InputStream inStream) throws EOFException, IOException {
        byte[] bytes = new byte[PEER_ADDRESS_SIZE];
        int count = inStream.read(bytes);
        if (count < PEER_ADDRESS_SIZE)
            throw new EOFException("End-of-data processing serialized address");
        timeSeen = Utils.readUint32LE(bytes, 0);
        services = Utils.readUint64LE(bytes, 4);
        boolean ipv4 = true;
        for (int j=0; j<12; j++) {
            if (bytes[j+12] != IPV6_PREFIX[j]) {
                ipv4 = false;
                break;
            }
        }
        if (ipv4)
            address = InetAddress.getByAddress(Arrays.copyOfRange(bytes, 24, 28));
        else
            address = InetAddress.getByAddress(Arrays.copyOfRange(bytes, 12, 28));
        port = (((int)bytes[28]&0xff)<<8) | ((int)bytes[29]&0xff);
    }

    /**
     * Returns the serialized address
     *
     * @return                      Serialized address
     */
    public byte[] getBytes() {
        byte[] bytes = new byte[PEER_ADDRESS_SIZE];
        getBytes(bytes, 0);
        return bytes;
    }

    /**
     * Returns the serialized address
     *
     * @param       bytes           Address buffer
     * @param       offset          Buffer offset
     */
    public void getBytes(byte[] bytes, int offset) {
        Utils.uint32ToByteArrayLE(timeSeen, bytes, offset);
        Utils.uint64ToByteArrayLE(services, bytes, offset+4);
        byte[] addrBytes = address.getAddress();
        if (addrBytes.length == 16) {
            System.arraycopy(addrBytes, 0, bytes, offset+12, 16);
        } else {
            System.arraycopy(IPV6_PREFIX, 0, bytes, offset+12, 12);
            System.arraycopy(addrBytes, 0, bytes, offset+24, 4);
        }
        bytes[offset+28] = (byte)(port>>8);
        bytes[offset+29] = (byte)port;
    }

    /**
     * Returns the IP address
     *
     * @return                      IP address
     */
    public InetAddress getAddress() {
        return address;
    }

    /**
     * Sets the IP address
     *
     * @param       address         IP address
     */
    public void setAddress(InetAddress address) {
        this.address = address;
    }

    /**
     * Returns the IP port
     *
     * @return                      IP port
     */
    public int getPort() {
        return port;
    }

    /**
     * Sets the IP port
     *
     * @param       port            IP port
     */
    public void setPort(int port) {
        this.port = port;
    }

    /**
     * Returns the timestamp for this peer
     *
     * @return      Timestamp in seconds since the epoch
     */
    public long getTimeStamp() {
        return timeSeen;
    }

    /**
     * Sets the timestamp for this peer
     *
     * @param       timeSeen        Time peer was seen in seconds since the epoch
     */
    public void setTimeStamp(long timeSeen) {
        this.timeSeen = timeSeen;
    }

    /**
     * Sets the peer services
     *
     * @param       services            Peer services
     */
    public void setServices(long services) {
        this.services = services;
    }

    /**
     * Returns the peer services
     *
     * @return      Peer services
     */
    public long getServices() {
        return services;
    }

    /**
     * Checks if this peer is connected
     *
     * @return      TRUE if the peer is connected
     */
    public boolean isConnected() {
        return connected;
    }

    /**
     * Sets the peer connection status
     *
     * @param       isConnected     TRUE if the peer is connected
     */
    public void setConnected(boolean isConnected) {
        connected = isConnected;
    }

    /**
     * Checks if this is an outbound connection
     *
     * @return      TRUE if this is an outbound connection
     */
    public boolean isOutbound() {
        return outboundConnection;
    }

    /**
     * Set the peer connection type
     *
     * @param       isOutbound          TRUE if this is an outbound connection
     */
    public void setOutbound(boolean isOutbound) {
        outboundConnection = isOutbound;
    }

    /**
     * Check if this is a static address
     *
     * @return      TRUE if this is a static address
     */
    public boolean isStatic() {
        return staticAddress;
    }

    /**
     * Set the address type
     *
     * @param       isStatic            TRUE if this is a static address
     */
    public void setStatic(boolean isStatic) {
        staticAddress = isStatic;
    }

    /**
     * Return a socket address for our IP address and port
     *
     * @return                      Socket address
     */
    public InetSocketAddress toSocketAddress() {
        return new InetSocketAddress(address, port);
    }

    /**
     * Returns a string representation of the IP address and port
     *
     * @return                      String representation
     */
    @Override
    public String toString() {
        return String.format("[%s]:%d", address.getHostAddress(), port);
    }

    /**
     * Checks if the supplied address is equal to this address
     *
     * @param       obj             Address to check
     * @return                      TRUE if the addresses are equal
     */
    @Override
    public boolean equals(Object obj) {
        boolean areEqual = false;
        if (obj != null && (obj instanceof PeerAddress)) {
            PeerAddress other = (PeerAddress)obj;
            areEqual = (address.equals(other.address) && port == other.port);
        }

        return areEqual;
    }

    /**
     * Returns the hash code for this object
     *
     * @return                      The hash code
     */
    @Override
    public int hashCode() {
        return (address.hashCode()^port);
    }
}
