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

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Arrays;

/**
 * A script is a small program contained in the transaction which determines whether or not
 * an output can be spent.  The first half of the script is provided by the transaction input
 * and the second half of the script is provided by the transaction output.
 */
public class Script {

    /** Logger instance */
    private static final Logger log = LoggerFactory.getLogger(Script.class);

    /** Maximum number of signature operations allowed */
    public static final int MAX_SIG_OPS = 20;

    /** Standard signature types */
    public static final int PAY_TO_PUBKEY_HASH = 1;
    public static final int PAY_TO_PUBKEY = 2;
    public static final int PAY_TO_SCRIPT_HASH = 3;
    public static final int PAY_TO_MULTISIG = 4;
    public static final int PAY_TO_NOBODY = 5;

    /** Signature hash types */
    public static final int SIGHASH_ALL = 1;
    public static final int SIGHASH_NONE = 2;
    public static final int SIGHASH_SINGLE = 3;
    public static final int SIGHASH_ANYONE_CAN_PAY = 128;

    /** Operations stack */
    private List<StackElement> stack = new ArrayList<>(20);

    /** Transaction input */
    private TransactionInput txInput;

    /** Script for connected output */
    private byte[] outputScriptBytes;

    /** Combined script program */
    private byte[] program;

    /** Pay-to-script-hash indicator */
    private boolean pay2ScriptHash;

    /**
     * Creates a new instance of the script processor
     *
     * @param       txInput             Transaction input
     * @param       outputScriptBytes   Script for connected output
     * @throws      ScriptException     Error while processing script
     */
    public Script(TransactionInput txInput, byte[] outputScriptBytes) throws ScriptException {
        this.txInput = txInput;
        this.outputScriptBytes = outputScriptBytes;
        byte[] inputScriptBytes = txInput.getScriptBytes();
        if (inputScriptBytes.length == 0)
            throw new ScriptException(String.format("Input %d does not have a script\n Input tx %s",
                                                    txInput.getIndex(),
                                                    txInput.getTransaction().getHash().toString()));
        if (outputScriptBytes.length == 0)
            throw new ScriptException(String.format("Connected output %d does not have a script\n Output tx %s",
                                                    txInput.getOutPoint().getIndex(),
                                                    txInput.getOutPoint().getHash().toString()));
        //
        // The script program consists of the input script followed by the output script
        //
        program = new byte[inputScriptBytes.length+outputScriptBytes.length];
        System.arraycopy(inputScriptBytes, 0, program, 0, inputScriptBytes.length);
        System.arraycopy(outputScriptBytes, 0, program, inputScriptBytes.length, outputScriptBytes.length);
        //
        // Check for a pay-to-script-hash output (BIP0016)
        //
        // The output script: OP_HASH160 <20-byte hash> OP_EQUAL
        // The inputs script: can contain only data elements
        //
        if (outputScriptBytes.length == 23 && outputScriptBytes[0] == (byte)ScriptOpCodes.OP_HASH160 &&
                                              outputScriptBytes[1] == 20 &&
                                              outputScriptBytes[22] == (byte)ScriptOpCodes.OP_EQUAL) {
            int offset = 0;
            pay2ScriptHash = true;
            try {
                while (offset < inputScriptBytes.length) {
                    int opcode = (int)inputScriptBytes[offset++]&0xff;
                    if (opcode <= ScriptOpCodes.OP_PUSHDATA4) {
                        int[] result = getDataLength(opcode, inputScriptBytes, offset);
                        offset = result[0] + result[1];
                    } else {
                        pay2ScriptHash = false;
                        break;
                    }
                }
            } catch (EOFException exc) {
                log.error("End of datat reached while scanning input script", exc);
                Main.dumpData("Failing Input Script", inputScriptBytes);
                throw new ScriptException("End of data reached while scanning input script");
            }
        }
    }

    /**
     * Checks that the script consists of only push-data operations.
     *
     * For canonical scripts, each push-data operation must use the shortest opcode possible.
     * Numeric values between 0 and 16 must use OP_n opcodes.
     *
     * @param       scriptBytes     Script bytes
     * @param       canonical       TRUE for canonical checking
     * @return                      TRUE if only canonical push-data operations were found
     * @throws      EOFException    Script is too short
     */
    public static boolean checkInputScript(byte[] scriptBytes, boolean canonical) throws EOFException {
        boolean scriptValid = true;
        int offset = 0;
        int length = scriptBytes.length;
        while (scriptValid && offset < length) {
            int opcode = ((int)scriptBytes[offset++])&0xff;
            if (opcode <= ScriptOpCodes.OP_PUSHDATA4) {
                int[] result = getDataLength(opcode, scriptBytes, offset);
                int dataLength = result[0];
                offset = result[1];
                if (canonical) {
                    if (dataLength == 1) {
                        if (opcode != 1 || ((int)scriptBytes[offset]&0xff) <= 16) {
                            log.warn("Pushing numeric value between 0 and 16");
                            scriptValid = false;
                        }
                    } else if (dataLength < 76) {
                        if (opcode >= ScriptOpCodes.OP_PUSHDATA1) {
                            log.warn("Pushing data length less than 76 with multi-byte opcode");
                            scriptValid = false;
                        }
                    } else if (dataLength < 256) {
                        if (opcode != ScriptOpCodes.OP_PUSHDATA1) {
                            log.warn("Pushing data length less than 256 with multi-byte opcode");
                            scriptValid = false;
                        }
                    } else if (dataLength < 65536) {
                        if (opcode != ScriptOpCodes.OP_PUSHDATA2) {
                            log.warn("Pushing data length less than 65536 with multi-byte opcode");
                            scriptValid = false;
                        }
                    }
                }
                offset += dataLength;
                if (offset > length)
                    throw new EOFException("End-of-data while processing script");
            } else if (opcode > ScriptOpCodes.OP_16) {
                log.warn("Non-pushdata opcode");
                scriptValid = false;
            }
        }
        if (!scriptValid)
            Main.dumpData("Failing Input Script", scriptBytes);
        return scriptValid;
    }

    /**
     * Get the input data elements
     *
     * @param       scriptBytes     Script bytes
     * @return                      Data element list
     * @throws      EOFException    Script is too short
     */
    public static List<byte[]> getData(byte[] scriptBytes) throws EOFException {
        List<byte[]> dataList = new LinkedList<>();
        int offset = 0;
        int length = scriptBytes.length;
        while (offset<length) {
            int dataLength = -1;
            int opcode = ((int)scriptBytes[offset++])&0xff;
            if (opcode <= ScriptOpCodes.OP_PUSHDATA4) {
                int[] result = getDataLength(opcode, scriptBytes, offset);
                dataLength = result[0];
                offset = result[1];
                if (dataLength > 0) {
                    if (offset+dataLength > length)
                        throw new EOFException("End-of-data while processing script");
                    dataList.add(Arrays.copyOfRange(scriptBytes, offset, offset+dataLength));
                    offset += dataLength;
                }
            }
        }
        return dataList;
    }

    /**
     * Count the number of signature operations in a script
     *
     * OP_CHECKSIG and OP_CHECKSIGVERIFY count as 1 signature operation
     *
     * OP_CHECKMULTISIG and OP_CHECKMULTISIGVERIFY count as n signature operations where
     * n is the number of pubkeys preceding the opcode.
     *
     * @param       scriptBytes         Script bytes
     * @return                          TRUE if the number of signature operations is acceptable
     * @throws      EOFException        Script is too short
     */
    public static boolean countSigOps(byte[] scriptBytes) throws EOFException {
        int sigCount = 0;
        int offset = 0;
        int length = scriptBytes.length;
        while (offset < length) {
            int opcode = ((int)scriptBytes[offset++])&0xff;
            if (opcode <= ScriptOpCodes.OP_PUSHDATA4) {
                int[] result = getDataLength(opcode, scriptBytes, offset);
                int dataLength = result[0];
                offset = result[1];
                offset += dataLength;
                if (offset > length)
                    throw new EOFException("End-of-data while processing script");
            } else if (opcode == ScriptOpCodes.OP_CHECKSIG || opcode == ScriptOpCodes.OP_CHECKSIGVERIFY) {
                // OP_CHECKSIG counts as 1 signature operation
                sigCount++;
            } else if (opcode == ScriptOpCodes.OP_CHECKMULTISIG ||   opcode == ScriptOpCodes.OP_CHECKMULTISIGVERIFY) {
                // OP_CHECKMULTISIG counts as 1 signature operation for each pubkey
                if (offset > 1) {
                    int keyCount = ((int)scriptBytes[offset-2])&0xff;
                    if (keyCount>=81 && keyCount<=96)
                        sigCount += keyCount-80;
                }
            }
        }
        return (sigCount<=MAX_SIG_OPS);
    }

    /**
     * Checks script data elements against a Bloom filter
     *
     * @param       filter              Bloom filter
     * @param       scriptBytes         Script to check
     * @return                          TRUE if a data element in the script matched the filter
     */
    public static boolean checkFilter(BloomFilter filter, byte[] scriptBytes) {
        boolean foundMatch = false;
        int offset = 0;
        int length = scriptBytes.length;
        //
        // Check each data element in the script
        //
        try {
            while (offset<length && !foundMatch) {
                int dataLength = -1;
                int opcode = ((int)scriptBytes[offset++])&0xff;
                if (opcode <= ScriptOpCodes.OP_PUSHDATA4) {
                    //
                    // Get the data element
                    //
                    int[] result = getDataLength(opcode, scriptBytes, offset);
                    dataLength = result[0];
                    offset = result[1];
                    if (dataLength > 0) {
                        if (offset+dataLength > length)
                            throw new EOFException("End-of-data while processing script");
                        foundMatch = filter.contains(scriptBytes, offset, dataLength);
                        offset += dataLength;
                    }
                }
            }
        } catch (EOFException exc) {
            log.warn("Unable to check script against Bloom filter", exc);
            Main.dumpData("Failing Script Program", scriptBytes);
        }
        return foundMatch;
    }

    /**
     * Returns the payment type for an output script
     *
     * @param       scriptBytes         Script to check
     * @return      Payment type or 0 if not a standard payment type
     */
    public static int getPaymentType(byte[] scriptBytes) {
        int paymentType = 0;
        if (scriptBytes.length > 0) {
            if (scriptBytes[0] == (byte)ScriptOpCodes.OP_RETURN) {
                //
                // Scripts starting with OP_RETURN are unspendable
                //
                paymentType = PAY_TO_NOBODY;
            } else if (scriptBytes[0] == (byte)ScriptOpCodes.OP_DUP) {
                //
                // Check PAY_TO_PUBKEY_HASH
                //   OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
                //
                if (scriptBytes.length == 25 && scriptBytes[1] == (byte)ScriptOpCodes.OP_HASH160 &&
                                                scriptBytes[2] == 20 &&
                                                scriptBytes[23] == (byte)ScriptOpCodes.OP_EQUALVERIFY &&
                                                scriptBytes[24] == (byte)ScriptOpCodes.OP_CHECKSIG)
                    paymentType = PAY_TO_PUBKEY_HASH;
            } else if (((int)scriptBytes[0]&0xff) <= 65) {
                //
                // Check PAY_TO_PUBKEY
                //   <pubkey> OP_CHECKSIG
                //
                int length = (int)scriptBytes[0];
                if (scriptBytes.length == length+2 && scriptBytes[length+1] == (byte)ScriptOpCodes.OP_CHECKSIG)
                    paymentType = PAY_TO_PUBKEY;
            } else if (scriptBytes[0] == (byte)ScriptOpCodes.OP_HASH160) {
                //
                // Check PAY_TO_SCRIPT_HASH
                //   OP_HASH160 <20-byte hash> OP_EQUAL
                //
                if (scriptBytes.length == 23 && scriptBytes[1] == 20 &&
                                                scriptBytes[22] == (byte)ScriptOpCodes.OP_EQUAL)
                    paymentType = PAY_TO_SCRIPT_HASH;
            } else if (((int)scriptBytes[0]&0xff) >= 81 && ((int)scriptBytes[0]&0xff) <= 96) {
                //
                // Check PAY_TO_MULTISIG
                //   <m> <pubkey> <pubkey> ... <n> OP_CHECKMULTISIG
                //
                int offset = 1;
                while (offset < scriptBytes.length) {
                    int opcode = (int)scriptBytes[offset]&0xff;
                    if (opcode <= 65) {
                        //
                        // We have another pubkey - step over it
                        //
                        offset += opcode+1;
                        continue;
                    }
                    if (opcode >= 81 && opcode <= 96) {
                        //
                        // We have found <n>
                        //
                        if (scriptBytes.length == offset+2 &&
                                        scriptBytes[offset+1] == (byte)ScriptOpCodes.OP_CHECKMULTISIG)
                            paymentType = PAY_TO_MULTISIG;
                    }
                    break;
                }
            }
        }
        return paymentType;
    }

    /**
     * Run the supplied script
     *
     * @return      TRUE if the script returns TRUE or FALSE if the script is invalid or returns FALSE;
     * @throws      ScriptException     Error while processing the script
     */
    public boolean runScript() throws ScriptException {
        boolean scriptResult;
        byte[] savedOutputScript = outputScriptBytes;
        boolean saveP2SH = pay2ScriptHash;
        try {
            scriptResult = processScript(program);
            if (!scriptResult) {
                log.warn(String.format("Script verification failed\n Tx %s",
                                       txInput.getTransaction().getHash().toString()));
                Main.dumpData("Failing ScriptProgram", program, program.length);
            }
        } catch (EOFException exc) {
            log.error(String.format("Unable to process script\n Tx %s",
                                    txInput.getTransaction().getHash().toString()), exc);
            Main.dumpData("Failing Script Program", program, program.length);
            throw new ScriptException("Unable to process script");
        } catch (ScriptException exc) {
            log.error(String.format("Script error detected\n Tx %s",
                                    txInput.getTransaction().getHash().toString()), exc);
            Main.dumpData("Failing Script Program", program, program.length);
            throw exc;
        } catch (Throwable exc) {
            log.error(String.format("Runtime exception while processing script\n Tx %s",
                                    txInput.getTransaction().getHash().toString()), exc);
            Main.dumpData("Failing Script Program", program, program.length);
            throw new ScriptException("Runtime exception while processing script");
        }
        stack.clear();
        outputScriptBytes = savedOutputScript;
        pay2ScriptHash = saveP2SH;
        return scriptResult;
    }

    /**
     * Process the script
     *
     * @param       program             Script program
     * @return      TRUE if the transaction is valid, FALSE otherwise
     * @throws      EOFException        Script is too short
     * @throws      IOException         I/O error while processing script
     * @throws      ScriptException     Error processing script
     */
    private boolean processScript(byte[] program) throws EOFException, IOException, ScriptException {
        int opcode;
        int dataToRead;
        int offset = 0;
        byte[] bytes;
        byte[] scriptBytes = program;
        byte[] hashedScript = null;
        boolean txValid = true;
        //
        // Process the input stream
        //
        while (txValid && offset<scriptBytes.length) {
            dataToRead = -1;
            opcode = (int)scriptBytes[offset++]&0xff;
            if (opcode <= ScriptOpCodes.OP_PUSHDATA4) {
                int[] result = getDataLength(opcode, scriptBytes, offset);
                dataToRead = result[0];
                offset = result[1];
            } else if (opcode == ScriptOpCodes.OP_1NEGATE) {
                // Push -1 onto the stack
                bytes = new byte[1];
                bytes[0] = (byte)255;
                stack.add(new StackElement(bytes));
            } else if (opcode >= ScriptOpCodes.OP_1 && opcode <= ScriptOpCodes.OP_16) {
                // Push 1 to 16 onto the stack based on the opcode (0x51-0x60)
                bytes = new byte[1];
                bytes[0] = (byte)(opcode&0x0f);
                if (bytes[0] == 0)
                    bytes[0] = (byte)16;
                stack.add(new StackElement(bytes));
            } else if (opcode == ScriptOpCodes.OP_NOP) {
                // Do nothing opcode
            } else if (opcode == ScriptOpCodes.OP_VERIFY) {
                // Mark transaction invalid if top element is not TRUE.  Otherwise, remove top element.
                txValid = processVerify();
            } else if (opcode == ScriptOpCodes.OP_RETURN) {
                // Mark transaction invalid
                txValid = false;
            } else if (opcode == ScriptOpCodes.OP_DROP) {
                // Drop the top stack element
                if (!stack.isEmpty())
                    stack.remove(stack.size()-1);
            } else if (opcode == ScriptOpCodes.OP_DUP) {
                // Duplicate the top stack element
                if (!stack.isEmpty()) {
                    StackElement elem = stack.get(stack.size()-1);
                    stack.add(new StackElement(elem.getBytes()));
                }
            } else if (opcode == ScriptOpCodes.OP_EQUAL || opcode == ScriptOpCodes.OP_EQUALVERIFY) {
                // Push 1 (TRUE) if top two stack elements are equal, else push 0 (FALSE)
                bytes = new byte[1];
                StackElement elem1 = popStack();
                StackElement elem2 = popStack();
                if (elem1.equals(elem2))
                    bytes[0] = (byte)1;
                else
                    bytes[0] = (byte)0;
                stack.add(new StackElement(bytes));
                if (opcode == ScriptOpCodes.OP_EQUALVERIFY) {
                    txValid = processVerify();
                } else if (pay2ScriptHash && bytes[0]==1) {
                    // Remove TRUE from the stack so that we are left with just the remaining
                    // data elements from the input script.  Then replace the script program
                    // with the deserialized hashed script and start again.
                    popStack();
                    scriptBytes = hashedScript;
                    outputScriptBytes = hashedScript;
                    offset = 0;
                    pay2ScriptHash = false;
                }
            } else if (opcode == ScriptOpCodes.OP_NOT) {
                // Reverse the top stack element (TRUE->FALSE, FALSE->TRUE)
                StackElement elem = popStack();
                byte[] newBytes = new byte[1];
                if (elem.isTrue())
                    newBytes[0] = 0;
                else
                    newBytes[0] = 1;
                stack.add(new StackElement(newBytes));
            } else if (opcode == ScriptOpCodes.OP_SHA256) {
                // SHA-256 hash
                StackElement elem = popStack();
                bytes = Utils.singleDigest(elem.getBytes());
                stack.add(new StackElement(bytes));
            } else if (opcode == ScriptOpCodes.OP_HASH160) {
                // SHA-256 hash followed by RIPEMD160 hash of the top stack element
                StackElement elem = popStack();
                bytes = Utils.sha256Hash160(elem.getBytes());
                stack.add(new StackElement(bytes));
                // Save the hashed script if this is PAY_TO_SCRIPT_HASH
                if (pay2ScriptHash)
                    hashedScript = elem.getBytes();
            } else if (opcode == ScriptOpCodes.OP_HASH256) {
                // Double SHA-256 hash
                StackElement elem = popStack();
                bytes = Utils.doubleDigest(elem.getBytes());
                stack.add(new StackElement(bytes));
            } else if (opcode == ScriptOpCodes.OP_CHECKSIG || opcode == ScriptOpCodes.OP_CHECKSIGVERIFY) {
                processCheckSig();
                if (opcode == ScriptOpCodes.OP_CHECKSIGVERIFY)
                    processVerify();
            } else if (opcode == ScriptOpCodes.OP_CHECKMULTISIG || opcode == ScriptOpCodes.OP_CHECKMULTISIGVERIFY) {
                processMultiSig();
                if (opcode == ScriptOpCodes.OP_CHECKMULTISIGVERIFY)
                    processVerify();
            } else {
                log.error(String.format("Unsupported script opcode %s(%d)",
                                        ScriptOpCodes.getOpCodeName((byte)opcode), opcode));
                throw new ScriptException("Unsupported script opcode");
            }
            //
            // Create a stack element for a data push operation and add it to the stack
            //
            if (dataToRead >= 0) {
                if (offset+dataToRead > scriptBytes.length)
                    throw new EOFException("End-of-data while processing script");
                bytes = new byte[dataToRead];
                if (dataToRead > 0)
                    System.arraycopy(scriptBytes, offset, bytes, 0, dataToRead);
                offset += dataToRead;
                stack.add(new StackElement(bytes));
            }
        }
        //
        // The script is successful if a non-zero value is on the top of the stack
        //
        if (txValid) {
            if (stack.isEmpty()) {
                txValid = false;
            } else {
                StackElement elem = popStack();
                txValid = elem.isTrue();
            }
        }
        return txValid;
    }

    /**
     * Get the length of the next data element
     *
     * @param       opcode              Current opcode
     * @param       scriptBytes         Script program
     * @param       startOffset         Offset to byte following the opcode
     * @return      Array containing the data length and the offset to the data
     * @throws      EOFException        Script is too short
     */
    private static int[] getDataLength(int opcode, byte[] scriptBytes, int startOffset) throws EOFException {
        int[] result = new int[2];
        int offset = startOffset;
        int dataToRead;
        if (opcode < 76) {
            // These opcodes push data with a length equal to the opcode
            dataToRead = opcode;
        } else if (opcode == ScriptOpCodes.OP_PUSHDATA1) {
            // The data length is in the next byte
            if (offset > scriptBytes.length-1)
                throw new EOFException("End-of-data while processing script");
            dataToRead = (int)scriptBytes[offset]&0xff;
            offset++;
        } else if (opcode == ScriptOpCodes.OP_PUSHDATA2) {
            // The data length is in the next two bytes
            if (offset > scriptBytes.length-2)
                throw new EOFException("End-of-data while processing script");
            dataToRead = ((int)scriptBytes[offset]&0xff) | (((int)scriptBytes[offset+1]&0xff)<<8);
            offset += 2;
        } else if (opcode == ScriptOpCodes.OP_PUSHDATA4) {
            // The data length is in the next four bytes
            if (offset > scriptBytes.length-4)
                throw new EOFException("End-of-data while processing script");
            dataToRead = ((int)scriptBytes[offset]&0xff) |
                                    (((int)scriptBytes[offset+1]&0xff)<<8) |
                                    (((int)scriptBytes[offset+2]&0xff)<<16) |
                                    (((int)scriptBytes[offset+3]&0xff)<<24);
            offset += 4;
        } else {
            dataToRead = 0;
        }
        result[0] = dataToRead;
        result[1] = offset;
        return result;
    }

    /**
     * Pop the top element from the stack
     *
     * @return      The top stack element
     * @throws      ScriptException
     */
    private StackElement popStack() throws ScriptException {
        int index = stack.size()-1;
        if (index < 0)
            throw new ScriptException("Stack underrun");
        StackElement elem = stack.get(index);
        stack.remove(index);
        return elem;
    }

    /**
     * Process OP_VERIFY
     *
     * Checks the top element on the stack and removes it if it is non-zero.  The return value
     * is TRUE if the top element was non-zero and FALSE otherwise.
     */
    private boolean processVerify() {
        boolean txValid;
        int index = stack.size()-1;
        if (index < 0) {
            txValid = false;
        } else if (stack.get(index).isTrue()) {
            txValid = true;
            stack.remove(index);
        } else {
            txValid = false;
        }
        return txValid;
    }

    /**
     * Process OP_CHECKSIG
     *
     * The stack must contain the signature and the public key.  The public key is
     * used to verify the signature.  TRUE is pushed on the stack if the signature
     * is valid, otherwise FALSE is pushed on the stack.
     *
     * @throws      IOException
     * @throws      ScriptException
     */
    private void processCheckSig() throws IOException, ScriptException {
        byte[] bytes;
        boolean result;
        //
        // Check the signature
        //
        // Make sure the public key starts with x'02', x'03' or x'04'.  Otherwise,
        // Bouncycastle throws an illegal argument exception.  We will return FALSE
        // if we find an invalid public key.
        //
        StackElement pubKey = popStack();
        StackElement sig = popStack();
        bytes = pubKey.getBytes();
        if (bytes.length == 0) {
            log.warn("Null public key provided");
            result = false;
        } else if (!ECKey.isPubKeyCanonical(bytes)) {
            log.warn(String.format("Non-canonical public key: Key %s", Utils.bytesToHexString(bytes)));
            result = false;
        } else {
            List<StackElement> pubKeys = new ArrayList<>(2);
            pubKeys.add(pubKey);
            result = checkSig(sig.getBytes(), pubKeys);
        }
        //
        // Push the result on the stack
        //
        bytes = new byte[1];
        bytes[0] = (result ? (byte)1 : (byte)0);
        stack.add(new StackElement(bytes));
    }

    /**
     * Process OP_MULTISIG
     *
     * The stack must contain at least one signature and at least one public key.
     * Each public key is tested against each signature until a valid signature is
     * found.  All signatures must be verified but all public keys do not need to
     * be used.  A public key is removed from the list once it has been used to
     * verify a signature.
     *
     * TRUE is pushed on the stack if all signatures have been verified,
     * otherwise FALSE is pushed on the stack.
     */
    private void processMultiSig() throws IOException, ScriptException {
        List<StackElement> keys = new ArrayList<>(MAX_SIG_OPS);
        List<StackElement> sigs = new ArrayList<>(MAX_SIG_OPS);
        //
        // Get the public keys
        //
        // Some early transactions contain a garbage public key, so we need to check
        // for a valid initial byte (02, 03, 04).  The garbage key will be ignored
        // and the transaction will be valid as long as the signature is verified using
        // one of the valid keys.
        //
        byte[] bytes = popStack().getBytes();
        if (bytes.length != 1)
            throw new ScriptException("Invalid public key count for OP_CHECKMULTISIG");
        int keyCount = (int)bytes[0]&0xff;
        if (keyCount < 1)
            throw new ScriptException("No public keys for OP_CHECKMULTISIG");
        if (keyCount > MAX_SIG_OPS)
            throw new ScriptException("Too many public keys for OP_CHECKMULTISIG");
        for (int i=0; i<keyCount; i++) {
            StackElement elem = popStack();
            bytes = elem.getBytes();
            if (bytes.length == 0)
                log.warn("Null public key provided");
            else if (ECKey.isPubKeyCanonical(bytes))
                keys.add(elem);
            else
                log.warn(String.format("Non-canonical public key: Key %s", Utils.bytesToHexString(bytes)));
        }
        if (keys.isEmpty())
            throw new ScriptException("No valid public keys for OP_CHECKMULTISIG");
        //
        // Get the signatures
        //
        bytes = popStack().getBytes();
        if (bytes.length != 1)
            throw new ScriptException("Invalid signature count for OP_CHECKMULTISIG");
        int sigCount = (int)bytes[0]&0xff;
        if (sigCount < 1)
            throw new ScriptException("No signatures for OP_CHECKMULTISIG");
        if (sigCount > MAX_SIG_OPS)
            throw new ScriptException("Too many signatures for OP_CHECKMULTISIG");
        for (int i=0; i<sigCount; i++)
            sigs.add(popStack());
        //
        // Verify each signature and stop if we have a verification failure
        //
        // We will stop when all signatures have been verified or there are no more
        // public keys available
        //
        boolean isValid = true;
        for (StackElement sig : sigs) {
            if (keys.isEmpty()) {
                log.warn("Not enough keys provided for OP_CHECKMULTISIG");
                isValid = false;
                break;
            }
            bytes = sig.getBytes();
            if (bytes.length == 0) {
                log.warn("Null signature provided for OP_CHECKMULTISIG");
                isValid = false;
                break;
            }
            isValid = checkSig(bytes, keys);
            if (!isValid)
                break;
        }
        //
        // Push the result on the stack
        //
        bytes = new byte[1];
        bytes[0] = (isValid ? (byte)1 : (byte)0);
        stack.add(new StackElement(bytes));
    }

    /**
     * Checks the transaction signature
     *
     * The signature is valid if it is signed by one of the supplied public keys.
     *
     * @param       sigBytes        The signature bytes from the input script
     * @param       pubKeys         The public keys to be checked
     * @return      TRUE if the signature is valid, FALSE otherwise
     * @throw       IOException
     * @throw       ScriptException
     */
    private boolean checkSig(byte[] sigBytes, List<StackElement> pubKeys) throws IOException, ScriptException {
        boolean isValid = false;
        byte[] subProgram;
        //
        // Check for a canonical signature
        //
        if (!ECKey.isSignatureCanonical(sigBytes))
            throw new ScriptException("Signature is not canonical");
        //
        // Remove all occurrences of the signature from the output script and create a new program
        // (the signature is normally in the input script, so this step usually does nothing)
        //
        try (ByteArrayOutputStream outStream = new ByteArrayOutputStream(outputScriptBytes.length)) {
            int index = 0;
            int count = outputScriptBytes.length;
            while (index < count) {
                int startPos = index;
                int dataLength = 0;
                int opcode = ((int)outputScriptBytes[index++])&0x00ff;
                if (opcode < ScriptOpCodes.OP_PUSHDATA1) {
                    dataLength = opcode;
                } else if (opcode == ScriptOpCodes.OP_PUSHDATA1) {
                    dataLength = (int)outputScriptBytes[index++]&0x00ff;
                } else if (opcode == ScriptOpCodes.OP_PUSHDATA2) {
                    dataLength = ((int)outputScriptBytes[index++]&0x00ff) |
                                 (((int)outputScriptBytes[index++]&0x00ff)<<8);
                } else if (opcode == ScriptOpCodes.OP_PUSHDATA4) {
                    dataLength = ((int)outputScriptBytes[index++]&0x00ff) |
                                 (((int)outputScriptBytes[index++]&0x00ff)<<8) |
                                 (((int)outputScriptBytes[index++]&0x00ff)<<16) |
                                 (((int)outputScriptBytes[index++]&0x00ff)<<24);
                }
                boolean copyElement;
                if (dataLength == sigBytes.length) {
                    copyElement = false;
                    for (int i=0; i<dataLength; i++) {
                        if (sigBytes[i] != outputScriptBytes[index+i]) {
                            copyElement = true;
                            break;
                        }
                    }
                } else {
                    copyElement = true;
                }
                if (copyElement)
                    outStream.write(outputScriptBytes, startPos, index-startPos+dataLength);

                index += dataLength;
            }
            subProgram = outStream.toByteArray();
        }
        //
        // The hash type is the last byte of the signature.  Remove it and create a new
        // byte array containing the DER-encoded signature.
        //
        int hashType = (int)sigBytes[sigBytes.length-1]&0x00ff;
        byte[] encodedSig = new byte[sigBytes.length-1];
        System.arraycopy(sigBytes, 0, encodedSig, 0, encodedSig.length);
        //
        // Serialize the transaction and then add the hash type to the end of the data
        //
        byte[] txData;
        try (ByteArrayOutputStream outStream = new ByteArrayOutputStream(1024)) {
            Transaction tx = txInput.getTransaction();
            tx.serializeForSignature(txInput.getIndex(), hashType, subProgram, outStream);
            Utils.uint32ToByteStreamLE(hashType, outStream);
            txData = outStream.toByteArray();
        }
        //
        // Use the public keys to verify the signature for the hashed data.  Stop as
        // soon as we have a verified signature.  The public key will be removed from
        // the list if it verifies a signature to prevent one person from signing the
        // transaction multiple times.
        //
        Iterator<StackElement> it = pubKeys.iterator();
        while (it.hasNext()) {
            StackElement pubKey = it.next();
            ECKey ecKey = new ECKey(pubKey.getBytes());
            try {
                isValid = ecKey.verifySignature(txData, encodedSig);
            } catch (ECException exc) {
                log.error("Unable to verify signature - discarding failing public key", exc);
                it.remove();
            }
            //
            // Remove the public key from the list if the verification is successful
            //
            if (isValid) {
                it.remove();
                break;
            }
        }
        return isValid;
    }

    /**
     * A stack element is a series of zero or more bytes.  The stack consists of stack elements
     * that are added and removed as the script is interpreted.
     */
    private class StackElement {

        /** The bytes represented by this stack element */
        private byte[] bytes;

        /**
         * Creates a new stack element
         *
         * @param       bytes           The bytes for this element
         */
        private StackElement(byte[] bytes) {
            this.bytes = bytes;
        }

        /**
         * Returns the bytes for this stack element
         *
         * @return                      The bytes for this element
         */
        private byte[] getBytes() {
            return bytes;
        }

        /**
         * Tests if this element represents a TRUE or FALSE result.  Any non-zero value is TRUE
         * while any zero (positive or negative) is FALSE.  A zero-length stack element is FALSE.
         *
         * @return      TRUE or FALSE depending on the bytes in this element
         */
        private boolean isTrue() {
            boolean isTrue = false;
            for (int i=0; i<bytes.length && !isTrue; i++) {
                if (bytes[i] == (byte)0x80) {
                    if (i != bytes.length-1)
                        isTrue = true;
                } else if (bytes[i] != 0) {
                    isTrue = true;
                }
            }
            return isTrue;
        }

        /**
         * Return the hash code for this stack element
         *
         * @return      Hash code
         */
        @Override
        public int hashCode() {
            return Arrays.hashCode(bytes);
        }

        /**
         * Tests if two stack elements are equal
         *
         * @param       obj         Object to compare
         * @return      TRUE if the two objects are equal
         */
        @Override
        public boolean equals(Object obj) {
            boolean areEqual = false;
            if (obj != null && (obj instanceof StackElement))
                areEqual = Arrays.equals(bytes, ((StackElement)obj).bytes);

            return areEqual;
        }
    }
}
