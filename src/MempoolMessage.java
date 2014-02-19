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
import java.util.ArrayList;
import java.util.List;

/**
 * The 'mempool' message requests a list of transactions in the peer memory pool.
 * The response is an 'inv' message listing the transactions in the pool.
 *
 * The message consists of just the message header.
 */
public class MempoolMessage {

    /**
     * Processes a 'mempool' message and returns an 'inv' message in response
     *
     * @param       msg             Message
     * @param       inStream        Message data stream
     */
    public static void processMempoolMessage(Message msg, ByteArrayInputStream inStream) {
        //
        // Get the list of transaction identifiers in the memory pool (return a maximum
        // of 5000 entries)
        //
        List<Sha256Hash> txList;
        synchronized(Parameters.lock) {
            txList = new ArrayList<>(Parameters.txPool.size());
            for (StoredTransaction tx : Parameters.txPool) {
                txList.add(tx.getHash());
                if (txList.size() == 5000)
                    break;
            }
        }
        //
        // Build the 'inv' message
        //
        Message invMsg = InventoryMessage.buildInventoryMessage(msg.getPeer(), Parameters.INV_TX, txList);
        msg.setBuffer(invMsg.getBuffer());
        msg.setCommand(invMsg.getCommand());
    }
}
