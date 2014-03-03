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
import java.util.Arrays;

/**
  * <p>A transaction output has the following format:</p>
 * <pre>
 *   Size           Field               Description
 *   ====           =====               ===========
 *   8 bytes        TxOutValue          Value expressed in Satoshis (0.00000001 BTC)
 *   VarInt         TxOutScriptLength   Script length
 *   Variable       TxOutScript         Script
 * </pre>
 *
 * <p>All numbers are encoded in little-endian format (least-significant byte to most-significant byte)</p>
 */
public class TransactionOutput {

    /** Unspendable 'Proof-of-burn' script (1CounterpartyXXXX...) */
    private final byte[] unspendableScript = new byte[] {
        (byte)0x76, (byte)0xa9, (byte)0x14,
        (byte)0x81, (byte)0x88, (byte)0x95, (byte)0xf3, (byte)0xdc, (byte)0x2c, (byte)0x17, (byte)0x86,
        (byte)0x29, (byte)0xd3, (byte)0xd2, (byte)0xd8, (byte)0xfa, (byte)0x3e, (byte)0xc4, (byte)0xa3,
        (byte)0xf8, (byte)0x17, (byte)0x98, (byte)0x21,
        (byte)0x88, (byte)0xac
    };

    /** Output value in Satoshis (0.00000001 BTC) */
    private BigInteger value;

    /** Transaction output index */
    private int txIndex;

    /** Output script */
    private byte[] scriptBytes;

    /**
     * Creates a transaction output from the encoded byte stream
     *
     * @param       txIndex                 Index within the transaction output list
     * @param       inStream                Input stream
     * @throws      EOFException            Input stream is too short
     * @throws      IOException             Error reading the input stream
     * @throws      VerificationException   Verification failed
     */
    public TransactionOutput(int txIndex, InputStream inStream)
                                throws EOFException, IOException, VerificationException {
        this.txIndex = txIndex;
        //
        // Get the amount
        //
        byte[] bytes = new byte[8];
        int count = inStream.read(bytes, 0, 8);
        if (count != 8)
            throw new EOFException("End-of-data while building TransactionOutput");
        value = BigInteger.valueOf(Utils.readUint64LE(bytes, 0));
        //
        // Get the script
        //
        int scriptCount = new VarInt(inStream).toInt();
        if (scriptCount < 0)
            throw new VerificationException("Script byte count is not valid");
        scriptBytes = new byte[scriptCount];
        if (scriptCount > 0) {
            count = inStream.read(scriptBytes);
            if (count != scriptCount)
                throw new EOFException("End-of-data while building TransactionOutput");
        }
    }

    /**
     * Returns the output amount
     *
     * @return      Output amount
     */
    public BigInteger getValue() {
        return value;
    }

    /**
     * Returns the transaction index for this output
     *
     * @return      Transaction index
     */
    public int getIndex() {
        return txIndex;
    }

    /**
     * Returns the script bytes
     *
     * @return      Script bytes or null
     */
    public byte[] getScriptBytes() {
        return scriptBytes;
    }

    /**
     * Checks if the output is spendable.  This is done by checking for OP_RETURN
     * as the first script operation.  Any script starting this way can never be
     * spent.  Note that an empty script is always spendable.
     *
     * Proof-of-burn transactions are sent to '1CounterpartyXXXXXXXXXXXXXXXUWLpVr'.
     * This address has no private key and thus can never be spent.  So we will
     * mark it as unspendable.
     *
     * @return                      TRUE if the output is spendable
     */
    public boolean isSpendable() {
        boolean spendable = true;
        if (scriptBytes.length > 0) {
            if (scriptBytes[0] == ScriptOpCodes.OP_RETURN)
                spendable = false;
            else if (Arrays.equals(scriptBytes, unspendableScript))
                spendable = false;
        }
        return spendable;
    }

    /**
     * Serializes this output for use in a transaction signature
     *
     * @param       index           Index of input being signed
     * @param       hashType        The signature hash type
     * @param       outStream       Output stream
     * @throws      IOException
     */
    public void serializeForSignature(int index, int hashType, OutputStream outStream) throws IOException {
        if (hashType == Script.SIGHASH_SINGLE && index != txIndex) {
            //
            // For SIGHASH_SINGLE, we have a zero-length script and a value of -1
            //
            Utils.uint64ToByteStreamLE(-1L, outStream);
            outStream.write(0);
        } else {
            //
            // Encode normally
            //
            Utils.uint64ToByteStreamLE(value, outStream);
            if (scriptBytes.length > 0) {
                outStream.write(VarInt.encode(scriptBytes.length));
                outStream.write(scriptBytes);
            } else {
                outStream.write(0);
            }
        }
    }
}
