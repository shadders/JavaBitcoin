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

import java.io.EOFException;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * <p>A transaction input has the following format:</p>
 * <pre>
 *   Size           Field               Description
 *   ===            =====               ===========
 *   32 bytes       TxOutHash           Double SHA-256 hash of the transaction containing the output
 *                                      to be used by this input
 *   4 bytes        TxOutIndex          Index of the output within the transaction
 *   VarInt         TxInScriptLength    Script length
 *   Variable       TxInScript          Script
 *   4 bytes        TxInSeqNumber       Input sequence number (irrelevant unless transaction LockTime is
 *                                      non-zero)
 * </pre>
 *
 * <p>All numbers are encoded in little-endian format (least-significant byte to most-significant byte)</p>
 */
public class TransactionInput {

    /** The transaction output connected to this input */
    private OutPoint outPoint;

    /** Input script */
    private byte[] scriptBytes;

    /** Input sequence number */
    private long seqNumber;

    /** Parent transaction */
    private Transaction tx;

    /** Transaction input index */
    private int txIndex;

    /**
     * Creates a transaction input from the encoded byte stream
     *
     * @param       tx              Parent transaction
     * @param       txIndex         Transaction input index
     * @param       inStream        Input stream
     * @throws      EOFException    Input stream is too short
     * @throws      IOException     Error reading the input stream
     * @throws      VerificationException  Verification error
     */
    public TransactionInput(Transaction tx, int txIndex, InputStream inStream)
                                    throws EOFException, IOException, VerificationException {
        this.tx = tx;
        this.txIndex = txIndex;
        //
        // Get the transaction output connected to this input
        //
        byte[] bytes = new byte[32];
        int count = inStream.read(bytes, 0, 32);
        if (count != 32)
            throw new EOFException("End-of-data while building TransactionInput");
        Sha256Hash prevTxHash = new Sha256Hash(Utils.reverseBytes(bytes, 0, 32));
        count = inStream.read(bytes, 0, 4);
        if (count != 4)
            throw new EOFException("Premature end-of-data while building TransactionInput");
        int prevTxIndex = (int)Utils.readUint32LE(bytes, 0);
        outPoint = new OutPoint(prevTxHash, prevTxIndex);
        //
        // Get the script (it is possible to not have a script)
        //
        int scriptCount = new VarInt(inStream).toInt();
        if (scriptCount < 0)
            throw new VerificationException("Script byte count is not valid");
        scriptBytes = new byte[scriptCount];
        if (scriptCount > 0) {
            count = inStream.read(scriptBytes);
            if (count != scriptCount)
                throw new EOFException("End-of-data while building TransactionInput");
        }
        //
        // Get the sequence number
        //
        count = inStream.read(bytes, 0, 4);
        if (count != 4)
            throw new EOFException("Premature end-of-data while building TransactionInput");
        seqNumber = Utils.readUint32LE(bytes, 0);
    }

    /**
     * Returns the transaction containing this input
     *
     * @return      Parent transaction
     */
    public Transaction getTransaction() {
        return tx;
    }

    /**
     * Return the index of this input within the transaction inputs
     *
     * @return      Transaction input index
     */
    public int getIndex() {
        return txIndex;
    }

    /**
     * Get the transaction output connected to this input
     *
     * @return      Transaction output
     */
    public OutPoint getOutPoint() {
        return outPoint;
    }

    /**
     * Returns the script bytes for this input
     *
     * @return      Script bytes or null
     */
    public byte[] getScriptBytes() {
        return scriptBytes;
    }

    /**
     * Returns the transaction sequence number
     *
     * @return      Transaction sequence number
     */
    public long getSeqNumber() {
        return seqNumber;
    }

    /**
     * Serializes this input for use in a transaction signature
     *
     * The scriptBytes are replaced by the supplied subScriptBytes.  In addition, the sequence number
     * is set to zero for all hash types other than SIGHASH_ALL.
     *
     * @param       index           Index of the input being signed
     * @param       hashType        Hash type
     * @param       subScriptBytes  Replacement script bytes
     * @param       outStream       Output stream
     * @throws      IOException
     */
    public void serializeForSignature(int index, int hashType, byte[] subScriptBytes, OutputStream outStream)
                                    throws IOException {
        outStream.write(Utils.reverseBytes(outPoint.getHash().getBytes()));
        Utils.uint32ToByteStreamLE(outPoint.getIndex(), outStream);
        outStream.write(VarInt.encode(subScriptBytes.length));
        if (subScriptBytes.length != 0)
            outStream.write(subScriptBytes);
        if (hashType == Script.SIGHASH_ALL)
            Utils.uint32ToByteStreamLE(seqNumber, outStream);
        else
            Utils.uint32ToByteStreamLE((index==txIndex?seqNumber:0), outStream);
    }
}
