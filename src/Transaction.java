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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;

import java.math.BigInteger;

import java.util.ArrayList;
import java.util.List;

/**
 * <p>A block is composed of one or more transactions.  The first transaction is called the coinbase transaction
 * and it assigns the block reward to the miner who solved the block hash.  The remaining transactions move coins
 * from Input A to Output B.  A single transaction can contain multiple inputs and multiple outputs.  The sum of
 * the inputs minus the sum of the output represents the mining fee for that transaction.</p>
 *
 * <p>Each transaction input is connected to the output of a proceeding transaction.  The input contains the
 * first half of a script (ScriptSig) and the output contains the second half (ScriptPubKey).  The script
 * is interpreted to determines if the transaction input is allowed to spend the transaction output.
 *
 * <p>A transaction has the following format:</p>
 * <pre>
 *   Size           Field               Description
 *   ====           =====               ===========
 *   4 bytes        Version             Currently 1
 *   VarInt         InputCount          Number of inputs
 *   Variable       InputList           Inputs
 *   VarInt         OutputCount         Number of outputs
 *   Variable       OutputList          Outputs
 *   4 bytes        LockTime            Transaction lock time
 * </pre>
 *
 * <p>All numbers are encoded in little-endian format (least-significant byte to most-significant byte)</p>
 */
public class Transaction {

    /** Logger instance */
    private static final Logger log = LoggerFactory.getLogger(Transaction.class);

    /** Serialized transaction data */
    private byte[] txData;

    /** Transaction version */
    private long txVersion;

    /** Transaction hash */
    private Sha256Hash txHash;

    /** Transaction lock time */
    private long txLockTime;

    /* This a coinbase transaction */
    private boolean coinBase;

    /** List of transaction inputs */
    private List<TransactionInput> txInputs;

    /** List of transaction outputs */
    private List<TransactionOutput> txOutputs;

    /**
     * Creates a new transaction from the serialized data in the byte stream
     *
     * @param       inStream        Byte stream
     * @throws      EOFException    Byte stream is too short
     * @throws      IOException     Error while reading the input stream
     * @throws      VerificationException  Verification error
     */
    public Transaction(SerializedInputStream inStream)
                                    throws EOFException, IOException, VerificationException {
        byte[] buf = new byte[4];
        //
        // Mark our current position within the input stream
        //
        inStream.setStart();
        //
        // Get the transaction version
        //
        int count = inStream.read(buf, 0, 4);
        if (count < 4)
            throw new EOFException("Premature end-of-data while building Transaction");
        txVersion = Utils.readUint32LE(buf, 0);
        //
        // Get the transaction inputs
        //
        int inCount = new VarInt(inStream).toInt();
        if (inCount < 0)
            throw new EOFException("Transaction input count is negative");
        txInputs = new ArrayList<>(Math.max(inCount, 1));
        for (int i=0; i<inCount; i++)
            txInputs.add(new TransactionInput(this, i, inStream));
        //
        // A coinbase transaction has a single unconnected input with a transaction hash of zero
        // and an output index of -1
        //
        if (txInputs.size() == 1) {
            OutPoint outPoint = txInputs.get(0).getOutPoint();
            if (outPoint.getHash().equals(Sha256Hash.ZERO_HASH) && outPoint.getIndex() == -1)
                coinBase = true;
        }
        //
        // Get the transaction outputs
        //
        int outCount = new VarInt(inStream).toInt();
        if (outCount < 0)
            throw new EOFException("Transaction output count is negative");
        txOutputs = new ArrayList<>(Math.max(outCount, 1));
        for (int i=0; i<outCount; i++)
            txOutputs.add(new TransactionOutput(i, inStream));
        //
        // Get the transaction lock time
        //
        count = inStream.read(buf, 0, 4);
        if (count < 4)
            throw new EOFException("Premature end-of-data while building Transaction");
        txLockTime = Utils.readUint32LE(buf, 0);
        //
        // Save a copy of the serialized transaction
        //
        txData = inStream.getBytes();
        //
        // Calculate the transaction hash using the serialized data
        //
        txHash = new Sha256Hash(Utils.reverseBytes(Utils.doubleDigest(txData)));
        //
        // Transaction must have at least one input and one output
        //
        if (inCount == 0)
            throw new VerificationException("Transaction has no inputs", Parameters.REJECT_INVALID, txHash);
        if (outCount == 0)
            throw new VerificationException("Transaction has no outputs", Parameters.REJECT_INVALID, txHash);
    }

    /**
     * Returns the transaction version
     *
     * @return      Transaction version
     */
    public long getVersion() {
        return txVersion;
    }

    /**
     * Returns the transaction lock time
     *
     * @return      Transaction lock time or zero
     */
    public long getLockTime() {
        return txLockTime;
    }

    /**
     * Returns the transaction hash
     *
     * @return      Transaction hash
     */
    public Sha256Hash getHash() {
        return txHash;
    }

    /**
     * Returns the transaction hash as a printable string
     *
     * @return      Transaction hash
     */
    public String getHashAsString() {
        return txHash.toString();
    }

    /**
     * Returns the list of transaction inputs
     *
     * @return      List of transaction inputs
     */
    public List<TransactionInput> getInputs() {
        return txInputs;
    }

    /**
     * Returns the list of transaction outputs
     *
     * @return      List of transaction outputs
     */
    public List<TransactionOutput> getOutputs() {
        return txOutputs;
    }

    /**
     * Checks if this is the coinbase transaction
     *
     * @return      TRUE if this is the coinbase transaction
     */
    public boolean isCoinBase() {
        return coinBase;
    }

    /**
     * Returns the original serialized transaction data
     *
     * @return      Serialized transaction data
     */
    public byte[] getBytes() {
        return txData;
    }

    /**
     * Returns the hash code for this transaction.  This is based on the transaction hash but is
     * not the same value.
     *
     * @return      Hash code
     */
    @Override
    public int hashCode() {
        return getHash().hashCode();
    }

    /**
     * Compare this transaction to another transaction to determine if they are equal.
     *
     * @param       obj             The transaction to compare
     * @return      TRUE if they are equal
     */
    @Override
    public boolean equals(Object obj) {
        boolean areEqual = false;
        if (obj != null && (obj instanceof Transaction))
            areEqual = getHash().equals(((Transaction)obj).getHash());

        return areEqual;
    }

    /**
     * Returns a string representation of this transaction
     *
     * @return      Formatted string
     */
    @Override
    public String toString() {
        return String.format("Transaction: %s\n  %d inputs, %d outputs, %s",
                              getHashAsString(), txInputs.size(), txOutputs.size(),
                              (coinBase ? "Coinbase" : "Not coinbase"));
    }

    /**
     * <p>Verify the transaction structure as follows</p>
     * <ul>
     * <li>A transaction must have at least one input and one output</li>
     * <li>A transaction output may not specify a negative number of coins</li>
     * <li>The sum of all of the output amounts must not exceed 21,000,000 BTC</li>
     * <li>The number of sigops in an output script must not exceed MAX_SIG_OPS</li>
     * <li>A non-coinbase transaction may not contain any unconnected inputs</li>
     * <li>A connected output may not be used by more than one input</li>
     * <li>The input script must contain only push-data operations</li>
     * </ul>
     *
     * @param       canonical                   TRUE to enforce canonical transactions
     * @throws      VerificationException       Script verification failed
     */
    public void verify(boolean canonical) throws VerificationException {
        byte[] scriptBytes = null;
        try {
            // Must have at least one input and one output
            if (txInputs.isEmpty() || txOutputs.isEmpty()) {
                log.error(String.format("Transaction does not have at least 1 input and 1 output\n  %s",
                                         txHash.toString()));
                throw new VerificationException("Transaction does not have at least 1 input and 1 output",
                                                Parameters.REJECT_INVALID, txHash);
            }
            // No output value may be negative
            // Sum of all output values must not exceed MAX_MONEY
            // The number of sigops in an output script may not exceed MAX_SIG_OPS
            BigInteger outTotal = BigInteger.ZERO;
            for (TransactionOutput txOut : txOutputs) {
                BigInteger outValue = txOut.getValue();
                if (outValue.signum() < 0) {
                    log.error(String.format("Transaction output value is negative\n  %s",
                                            txHash.toString()));
                    throw new VerificationException("Transaction output value is negative",
                                                    Parameters.REJECT_INVALID, txHash);
                }
                outTotal = outTotal.add(outValue);
                if (outTotal.compareTo(Parameters.MAX_MONEY) > 0) {
                    log.error(String.format("Total transaction output amount %s exceeds maximum\n  %s",
                                            outTotal.toString(), txHash.toString()));
                    throw new VerificationException("Total transaction output amount exceeds maximum",
                                                    Parameters.REJECT_INVALID, txHash);
                }
                scriptBytes = txOut.getScriptBytes();
                if (!Script.countSigOps(scriptBytes)) {
                    log.error(String.format("Too many signature operations\n  %s", txHash));
                    Main.dumpData("Failing Script", scriptBytes);
                    throw new VerificationException("Too many signature operations",
                                                    Parameters.REJECT_NONSTANDARD, txHash);
                }
            }
            if (!coinBase) {
                // All inputs must have connected outputs
                // No outpoint may be used more than once
                // Input scripts must consist of only push-data operations
                List<OutPoint> outPoints = new ArrayList<>(txInputs.size());
                for (TransactionInput txIn : txInputs) {
                    OutPoint outPoint = txIn.getOutPoint();
                    if (outPoint.getHash().equals(Sha256Hash.ZERO_HASH) || outPoint.getIndex() < 0) {
                        log.error(String.format("Non-coinbase transaction contains unconnected inputs\n  %s",
                                                txHash.toString()));
                        throw new VerificationException("Non-coinbase transaction contains unconnected inputs",
                                                        Parameters.REJECT_INVALID, txHash);
                    }
                    if (outPoints.contains(outPoint)) {
                        log.error(String.format("Connected output %s[%d] used in multiple inputs\n  %s",
                                                outPoint.getHash().toString(), outPoint.getIndex(), txHash));
                        throw new VerificationException("Connected output used in multiple inputs",
                                                        Parameters.REJECT_INVALID, txHash);
                    }
                    outPoints.add(outPoint);
                    scriptBytes = txIn.getScriptBytes();
                    if (!Script.checkInputScript(scriptBytes, canonical)) {
                        String errMsg;
                        if (canonical)
                            errMsg = "Input script must contain only canonical push-data operations";
                        else
                            errMsg = "Input script must contain only push-data operations";
                        log.error(String.format(errMsg+"\n  %s", txHash));
                        throw new VerificationException(errMsg, Parameters.REJECT_NONSTANDARD, txHash);
                    }
                }
            }
        } catch (EOFException exc) {
            log.error(String.format("End-of data while processing script\n  %s", txHash));
            Main.dumpData("Failing Script", scriptBytes);
            throw new VerificationException("End-of-data while processing script",
                                            Parameters.REJECT_MALFORMED, txHash);
        }
    }

    /**
     * Verifies the signature for the supplied input and output
     *
     * @param       txInput             Transaction input
     * @param       outputScriptBytes   Script for the connected output
     * @return      TRUE if signature is valid, FALSE otherwise
     */
    public boolean verifyInput(TransactionInput txInput, byte[] outputScriptBytes) {
        boolean valid;
        try {
            Script script = new Script(txInput, outputScriptBytes);
            valid = script.runScript();
        } catch (ScriptException exc) {
            log.warn("Unable to verify script", exc);
            valid = false;
        }
        return valid;
    }

    /**
     * Serializes the transaction for use in a signature
     *
     * @param       index               Current transaction index
     * @param       sigHashType         Signature hash type
     * @param       subScriptBytes      Replacement script for the current input
     * @param       outStream           The output stream
     * @throws      IOException
     * @throws      ScriptException
     */
    public void serializeForSignature(int index, int sigHashType, byte[] subScriptBytes, OutputStream outStream)
                                        throws IOException, ScriptException {
        int hashType;
        boolean anyoneCanPay;
        //
        // The transaction input must be within range
        //
        if (index < 0 || index >= txInputs.size()) {
            log.error(String.format("Transaction input index %d is not valid", index));
            throw new ScriptException("Transaction input index is not valid");
        }
        //
        // Check for a valid hash type
        //
        // Note that SIGHASH_ANYONE_CAN_PAY is or'ed with one of the other hash types.  So we need
        // to remove it when checking for a valid signature.
        //
        // SIGHASH_ALL:    This is the default. It indicates that everything about the transaction is signed
        //                 except for the input scripts. Signing the input scripts as well would obviously make
        //                 it impossible to construct a transaction.
        // SIGHASH_NONE:   The outputs are not signed and can be anything. This mode allows others to update
        //                 the transaction by changing their inputs sequence numbers.  This means that all
        //                 input sequence numbers are set to 0 except for the current input.
        // SIGHASH_SINGLE: Outputs up to and including the current input index number are included.  Outputs
        //                 before the current index have a -1 value and an empty script.  All input sequence
        //                 numbers are set to 0 except for the current input.
        //
        // The SIGHASH_ANYONE_CAN_PAY modifier can be combined with the above three modes. When set, only that
        // input is signed and the other inputs can be anything.
        //
        // In all cases, the script for the current input is replaced with the script from the connected
        // output.  All other input scripts are set to an empty script.
        //
        anyoneCanPay = ((sigHashType&Script.SIGHASH_ANYONE_CAN_PAY) != 0);
        hashType = sigHashType&(255-Script.SIGHASH_ANYONE_CAN_PAY);
        if (hashType != Script.SIGHASH_ALL && hashType != Script.SIGHASH_NONE && hashType != Script.SIGHASH_SINGLE) {
            log.error(String.format("Signature hash type %d is not supported", hashType));
            throw new ScriptException("Unsupported signature hash type");
        }
        //
        // Serialize the version
        //
        Utils.uint32ToByteStreamLE(txVersion, outStream);
        //
        // Serialize the inputs
        //
        // For SIGHASH_ANYONE_CAN_PAY, only the current input is included in the signature.
        // Otherwise, all inputs are included.
        //
        List<TransactionInput> sigInputs;
        if (anyoneCanPay) {
            sigInputs = new ArrayList<>(1);
            sigInputs.add(txInputs.get(index));
        } else {
            sigInputs = txInputs;
        }
        outStream.write(VarInt.encode(sigInputs.size()));
        byte[] emptyScriptBytes = new byte[0];
        for (TransactionInput txInput : sigInputs) {
            txInput.serializeForSignature(index, hashType,
                                          (txInput.getIndex()==index?subScriptBytes:emptyScriptBytes),
                                          outStream);
        }
        //
        // Serialize the outputs
        //
        if (hashType == Script.SIGHASH_NONE) {
            //
            // There are no outputs for SIGHASH_NONE
            //
            outStream.write(0);
        } else if (hashType == Script.SIGHASH_SINGLE) {
            //
            // The output list is resized to the input index+1
            //
            if (txOutputs.size() <= index) {
                log.error(String.format("Input index %d exceeds output size %d for SIGHASH_SINGLE",
                                         index, txOutputs.size()));
                throw new ScriptException("Input index out-of-range for SIGHASH_SINGLE");
            }
            outStream.write(VarInt.encode(index+1));
            for (TransactionOutput txOutput : txOutputs) {
                if (txOutput.getIndex() > index)
                    break;
                txOutput.serializeForSignature(index, hashType, outStream);
            }
        } else {
            //
            // All outputs are serialized for SIGHASH_ALL
            outStream.write(VarInt.encode(txOutputs.size()));
            for (TransactionOutput txOutput : txOutputs) {
                txOutput.serializeForSignature(index, hashType, outStream);
            }
        }
        //
        // Serialize the lock time
        //
        Utils.uint32ToByteStreamLE(txLockTime, outStream);
    }
}
