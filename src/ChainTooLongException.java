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
 * This exception is thrown when the block chain is too long to fit in storage
 */
public class ChainTooLongException extends BlockStoreException {

    /**
     * Creates a new exception with a detail message
     *
     * @param       message         Detail message
     */
    public ChainTooLongException(String message) {
        super(message);
    }

    /**
     * Creates a new exception with a detail message and a causing block
     *
     * @param       message         Detail message
     * @param       blockHash       Block hash
     */
    public ChainTooLongException(String message, Sha256Hash blockHash) {
        super(message, blockHash);
    }

    /**
     * Creates a new exception with a detail message and cause
     *
     * @param       message         Detail message
     * @param       e               Caught exception
     */
    public ChainTooLongException(String message, Exception t) {
        super(message, t);
    }

    /**
     * Creates a new exception with a detail message, causing block and causing exception
     *
     * @param       message         Detail message
     * @param       blockHash       Block hash
     * @param       t               Caught exception
     */
    public ChainTooLongException(String message, Sha256Hash blockHash, Throwable t) {
        super(message, blockHash, t);
    }
}
