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
import java.math.BigInteger;

/**
 * StoredOutput represents a transaction output when it is stored in the database
 */
public class StoredOutput {

    /** Index within the transaction output list */
    private int txIndex;

    /** Output value */
    private BigInteger value;

    /** Script bytes */
    private byte[] scriptBytes;

    /** Output spent flag */
    private boolean isSpent;

    /** Height for block spending this output */
    private int blockHeight;

    /**
     * Creates a new stored transaction output
     *
     * @param       txIndex             Index within the transaction output list
     * @param       value               Output value expressed in 0.00000001 BTC units
     * @param       scriptBytes         Script bytes
     */
    public StoredOutput(int txIndex, BigInteger value, byte[] scriptBytes) {
        this.txIndex = txIndex;
        this.value = value;
        this.scriptBytes = scriptBytes;
        this.isSpent = false;
    }

    /**
     * Creates a new stored transaction output
     *
     * @param       txIndex             Index within the transaction output list
     * @param       value               Output value expressed in 0.00000001 BTC units
     * @param       scriptBytes         Script bytes
     * @param       isSpent             TRUE if the output has been spent
     * @param       blockHeight         Chain height of block spending this output
     */
    public StoredOutput(int txIndex, BigInteger value, byte[] scriptBytes, boolean isSpent, int blockHeight) {
        this.txIndex = txIndex;
        this.value = value;
        this.scriptBytes = scriptBytes;
        this.isSpent = isSpent;
        this.blockHeight = blockHeight;
    }

    /**
     * Creates a new stored transaction output from the serialized data stream
     *
     * @param       stream              The input stream
     * @throws      EOFException
     * @throws      IOException
     */
    public StoredOutput(InputStream stream) throws EOFException, IOException {
        byte[] bytes = new byte[8];
        int count;
        count = stream.read(bytes, 0, 4);
        if (count != 4)
            throw new EOFException("End-of-data while building StoredOutput");
        txIndex = (int)Utils.readUint32LE(bytes, 0);
        count = stream.read(bytes, 0, 8);
        if (count != 8)
            throw new EOFException("End-of-data while building StoredOutput");
        value = BigInteger.valueOf(Utils.readUint64LE(bytes, 0));
        int spent = stream.read();
        if (spent < 0)
            throw new EOFException("End-of-data while building StoredOutput");
        boolean heightPresent;
        if ((spent&0x10) != 0) {
            heightPresent = true;
            spent &= 0x0f;
        } else {
            heightPresent = false;
        }
        isSpent = (spent!=0);
        int scriptCount = new VarInt(stream).toInt();
        if (scriptCount > 0) {
            scriptBytes = new byte[scriptCount];
            count = stream.read(scriptBytes);
            if (count != scriptCount)
                throw new EOFException("End-of-data while building StoredOutput");
        }
        if (heightPresent) {
            count = stream.read(bytes, 0, 4);
            if (count != 4)
                throw new EOFException("End-of-data while building StoredOutput");
            blockHeight = (int)Utils.readUint32LE(bytes, 0);
        }
    }

    /**
     * Serializes the StoredOutput instance
     *
     * @param       stream              The output stream
     * @throws      IOException
     */
    public void bitcoinSerialize(OutputStream stream) throws IOException {
        Utils.uint32ToByteStreamLE(txIndex, stream);
        Utils.uint64ToByteStreamLE(value, stream);
        stream.write(isSpent ? 0x11 : 0x10);
        if (scriptBytes != null) {
            stream.write(VarInt.encode(scriptBytes.length));
            stream.write(scriptBytes);
        } else {
            stream.write(0);
        }
        Utils.uint32ToByteStreamLE(blockHeight, stream);
    }

    /**
     * Returns the index within the transaction output list
     *
     * @return      Transaction output index
     */
    public int getIndex() {
        return txIndex;
    }

    /**
     * Returns the transaction output value
     *
     * @return      Transaction output value
     */
    public BigInteger getValue() {
        return value;
    }

    /**
     * Returns the script bytes for the transaction output
     *
     * @return      Script bytes or null
     */
    public byte[] getScriptBytes() {
        return scriptBytes;
    }

    /**
     * Sets the transaction output spent indicator
     *
     * @param       isSpent         TRUE if the transaction output has been spent
     */
    public void setSpent(boolean isSpent) {
        this.isSpent = isSpent;
    }

    /**
     * Checks if the transaction output has been spent
     *
     * @return      TRUE if the output has been spent
     */
    public boolean isSpent() {
        return isSpent;
    }

    /**
     * Set the block height for the block spending this output
     *
     * @param       blockHeight     Block height
     */
    public void setHeight(int blockHeight) {
        this.blockHeight = blockHeight;
    }

    /**
     * Returns the block height for the block spending this output.  The return value
     * will be zero if the block height is not available.
     *
     * @return      Block height or zero
     */
    public int getHeight() {
        return blockHeight;
    }
}
