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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;

/**
 * <p>The 'merkleblock' message is sent in response to a 'getdata' block request
 * and the requesting peer has set a Bloom filter.  In this case, the response is just the
 * block header and a Merkle branch representing the matching transactions.</p>
 *
 * <p>MerkleBlock Message</p>
 * <pre>
 *   Size       Field           Description
 *   ====       =====           ===========
 *   4 bytes    Version         The block version number
 *   32 bytes   PrevBlockHash   The hash of the preceding block in the chain
 *   32 byte    MerkleRoot      The Merkle root for the transactions in the block
 *   4 bytes    Time            The time the block was mined
 *   4 bytes    Difficulty      The target difficulty
 *   4 bytes    Nonce           The nonce used to generate the required hash
 *   4 bytes    txCount         Number of transactions in the block
 *   VarInt     hashCount       Number of hashes
 *   Variable   hashes          Hashes in depth-first order
 *   VarInt     flagCount       Number of bytes of flag bits
 *   Variable   flagBits        Flag bits packed 8 per byte, least significant bit first
 * </pre>
 */
public class MerkleBlockMessage {

    /**
     * Builds the 'merkleblock' message
     *
     * @param       peer            Destination peer
     * @param       block           Block to be sent to the peer
     * @param       indexList       List of matching transaction indexes
     * @return                      Message to be sent to the peer
     * @throws      IOException     Unable to create the message data
     */
    public static Message buildMerkleBlockMessage(Peer peer, Block block, List<Integer> indexList)
                                throws IOException {
        List<Transaction> txList = block.getTransactions();
        ByteArrayOutputStream outStream = new ByteArrayOutputStream(Block.HEADER_SIZE+txList.size()*32);
        //
        // The first 80 bytes are the block header
        //
        byte[] blockData = block.bitcoinSerialize();
        outStream.write(blockData, 0, Block.HEADER_SIZE);
        //
        // Create the Merkle branch
        //
        List<byte[]> merkleTree = block.getMerkleTree();
        MerkleBranch branch = new MerkleBranch(txList.size(), indexList, merkleTree);
        branch.bitcoinSerialize(outStream);
        //
        // Create the message
        //
        byte[] msgData = outStream.toByteArray();
        outStream.close();
        ByteBuffer buffer = MessageHeader.buildMessage("merkleblock", msgData);
        return new Message(buffer, peer, MessageHeader.MERKLEBLOCK_CMD);
    }
}
