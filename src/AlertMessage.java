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

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;

/**
 * <p>The 'alert' message is sent out by the development team to notify all peers in the network
 * about a problem.  The alert is displayed in the user interface and written to the
 * log.  It is also sent each time a node connects to another node until the relay time
 * is exceeded or the alert is canceled.</p>
 *
 * <p>The 'alert' message contains two variable-length byte arrays.  The first array is the
 * payload and the second array is the signature.  The alert is packaged this way so that
 * a peer at any level can relay the alert even if it doesn't understand the alert format.</p>
 *
 * <p>Alert Message</p>
 * <pre>
 *   Size       Field           Description
 *   ====       =====           ===========
 *   VarInt     PayloadLength   Length of the payload
 *   Variable   Payload         Alert payload
 *   VarInt     SigLength       Length of the signature
 *   Variable   Signature       Alert signature
 * </pre>
 */
public class AlertMessage {

    /** Public key used to verify an alert */
    private static final byte[] alertPubKey = {
        (byte)0x04, (byte)0xfc, (byte)0x97, (byte)0x02, (byte)0x84, (byte)0x78, (byte)0x40, (byte)0xaa,
        (byte)0xf1, (byte)0x95, (byte)0xde, (byte)0x84, (byte)0x42, (byte)0xeb, (byte)0xec, (byte)0xed,
        (byte)0xf5, (byte)0xb0, (byte)0x95, (byte)0xcd, (byte)0xbb, (byte)0x9b, (byte)0xc7, (byte)0x16,
        (byte)0xbd, (byte)0xa9, (byte)0x11, (byte)0x09, (byte)0x71, (byte)0xb2, (byte)0x8a, (byte)0x49,
        (byte)0xe0, (byte)0xea, (byte)0xd8, (byte)0x56, (byte)0x4f, (byte)0xf0, (byte)0xdb, (byte)0x22,
        (byte)0x20, (byte)0x9e, (byte)0x03, (byte)0x74, (byte)0x78, (byte)0x2c, (byte)0x09, (byte)0x3b,
        (byte)0xb8, (byte)0x99, (byte)0x69, (byte)0x2d, (byte)0x52, (byte)0x4e, (byte)0x9d, (byte)0x6a,
        (byte)0x69, (byte)0x56, (byte)0xe7, (byte)0xc5, (byte)0xec, (byte)0xbc, (byte)0xd6, (byte)0x82,
        (byte)0x84};

    /**
     * Create an 'alert' message
     *
     * @param       peer                    Destination peer or null for a broadcast message
     * @param       alert                   The alert
     * @return      The 'alert' message
     */
    public static Message buildAlertMessage(Peer peer, Alert alert) {
        byte[] payload = alert.getPayload();
        byte[] signature = alert.getSignature();
        byte[] payLength = VarInt.encode(payload.length);
        byte[] sigLength = VarInt.encode(signature.length);
        byte[] msgData = new byte[payLength.length+payload.length+sigLength.length+signature.length];
        //
        // Build the message data
        //
        System.arraycopy(payLength, 0, msgData, 0, payLength.length);
        int offset = payLength.length;
        System.arraycopy(payload, 0, msgData, offset, payload.length);
        offset += payload.length;
        System.arraycopy(sigLength, 0, msgData, offset, sigLength.length);
        offset += sigLength.length;
        System.arraycopy(signature, 0, msgData, offset, signature.length);
        //
        // Build the message
        //
        ByteBuffer buffer = MessageHeader.buildMessage("alert", msgData);
        return new Message(buffer, peer, MessageHeader.ALERT_CMD);
    }

    /**
     * Process an 'alert' message
     *
     * @param       msg                     Message
     * @param       inStream                Message data stream
     * @throws      EOFException            End-of-data while processing message data
     * @throws      IOException             Unable to read message data
     * @throws      VerificationException   Message verification failed
     */
    public static void processAlertMessage(Message msg, ByteArrayInputStream inStream)
                                           throws EOFException, IOException, VerificationException {
        //
        // Process the message data
        //
        int payLength = new VarInt(inStream).toInt();
        if (payLength < 0 || payLength > 1000)
            throw new VerificationException("Alert message payload is longer than 1000 bytes");
        byte[] payload = new byte[payLength];
        int count = inStream.read(payload);
        if (count != payLength)
            throw new EOFException("End-of-data while processing 'alert' message");
        int sigLength = new VarInt(inStream).toInt();
        if (sigLength < 0 || sigLength > 80)
            throw new EOFException("Signature is longer than 80 bytes");
        byte[] signature = new byte[sigLength];
        count = inStream.read(signature);
        if (count != sigLength)
            throw new EOFException("End-of-data while processing 'alert' message");
        //
        // Verify the signature
        //
        boolean isValid = false;
        ECKey ecKey = new ECKey(alertPubKey);
        try {
            isValid = ecKey.verifySignature(payload, signature);
        } catch (ECException exc) {
            throw new VerificationException("Alert signature verification failed", exc);
        }
        if (!isValid)
            throw new VerificationException("Alert signature is not valid");
        //
        // Process the alert
        //
        try {
            Alert alert = new Alert(payload, signature);
            if (Parameters.blockStore.isNewAlert(alert.getID())) {
                //
                // Store the alert in our database
                //
                Parameters.blockStore.storeAlert(alert);
                //
                // Process alert cancels
                //
                int cancelID = alert.getCancelID();
                if (cancelID != 0)
                    Parameters.blockStore.cancelAlert(cancelID);
                List<Integer> cancelSet = alert.getCancelSet();
                for (Integer id : cancelSet)
                    Parameters.blockStore.cancelAlert(id.intValue());
                //
                // Broadcast the alert to our peers
                //
                Message alertMsg = buildAlertMessage(null, alert);
                Parameters.networkListener.broadcastMessage(alertMsg);
            }
        } catch (BlockStoreException exc) {
            throw new IOException("Unable to store alert in database", exc);
        }
    }
}
