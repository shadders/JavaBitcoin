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

/**
 * This exception is thrown when an error is detected while storing a block
 */
public class BlockStoreException extends Exception {

    /** The block causing the exception */
    protected Sha256Hash blockHash;

    /**
     * Creates a new exception with a detail message
     *
     * @param       message         Detail message
     */
    public BlockStoreException(String message) {
        super(message);
        blockHash = Sha256Hash.ZERO_HASH;
    }

    /**
     * Creates a new exception with a detail message and a causing block
     *
     * @param       message         Detail message
     * @param       blockHash       Block hash
     */
    public BlockStoreException(String message, Sha256Hash blockHash) {
        super(message);
        this.blockHash = blockHash;
    }

    /**
     * Creates a new exception with a detail message and cause
     *
     * @param       message         Detail message
     * @param       t               Caught exception
     */
    public BlockStoreException(String message, Throwable t) {
        super(message, t);
        blockHash = Sha256Hash.ZERO_HASH;
    }

    /**
     * Creates a new exception with a detail message, causing block and causing exception
     *
     * @param       message         Detail message
     * @param       blockHash       Block hash
     * @param       t               Caught exception
     */
    public BlockStoreException(String message, Sha256Hash blockHash, Throwable t) {
        super(message, t);
        this.blockHash = blockHash;
    }

    /**
     * Returns the block hash for the block causing the exception
     *
     * @return      Block hash
     */
    public Sha256Hash getHash() {
        return blockHash;
    }
}
