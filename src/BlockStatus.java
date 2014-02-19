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
 *  BlockStatus contains the current status for a block in the StoredBlocks table
 */
public class BlockStatus {

    /** Block timestamp */
    private long timeStamp;

    /** Block hash */
    private Sha256Hash blockHash;

    /** Block height */
    private int blockHeight;

    /** Block chain status */
    private boolean onChain;

    /** Block hold status */
    private boolean onHold;

    /**
     * Creates a new BlockStatus
     *
     * @param       blockHash           Block hash
     * @param       timeStamp           Time block created
     * @param       blockHeight         Block height
     * @param       onChain             Block chain status
     * @param       onHold              Block hold status
     */
    public BlockStatus(Sha256Hash blockHash, long timeStamp, int blockHeight, boolean onChain, boolean onHold) {
        this.blockHash = blockHash;
        this.timeStamp = timeStamp;
        this.blockHeight = blockHeight;
        this.onChain = onChain;
        this.onHold = onHold;
    }

    /**
     * Returns the block hash
     *
     * @return      Block hash
     */
    public Sha256Hash getHash() {
        return blockHash;
    }

    /**
     * Returns the block timestamp
     *
     * @return      Time stamp in seconds since Jan 1, 1970
     */
    public long getTimeStamp() {
        return timeStamp;
    }

    /**
     * Returns the block height
     *
     * @return      Block height or zero if the block chain has not been resolved
     */
    public int getHeight() {
        return blockHeight;
    }

    /**
     * Sets the block height
     *
     * @param       height          The block height
     */
    public void setHeight(int height) {
        blockHeight = height;
    }

    /**
     * Checks if the block is on the main chain
     *
     * @return      TRUE if the block is on the main chain
     */
    public boolean isOnChain() {
        return onChain;
    }

    /**
     * Set the chain status
     *
     * @param       onChain         TRUE if the block is on the chain
     */
    public void setChain(boolean onChain) {
        this.onChain = onChain;
    }

    /**
     * Checks of the block is on hold
     *
     * @return      TRUE if the block is on hold
     */
    public boolean isOnHold() {
        return onHold;
    }

    /**
     * Set the hold status
     *
     * @param       onHold          TRUE if the block is on hold
     */
    public void setHold(boolean onHold) {
        this.onHold = onHold;
    }

    /**
     * Returns the hash code for this object
     *
     * @return      Hash code
     */
    @Override
    public int hashCode() {
        return blockHash.hashCode();
    }

    /**
     * Checks if two objects are equal
     *
     * @param       obj             Object to compare
     * @return      TRUE if the objects are equal
     */
    @Override
    public boolean equals(Object obj) {
        boolean areEqual = false;
        if (obj != null && (obj instanceof BlockStatus))
            areEqual = blockHash.equals(((BlockStatus)obj).blockHash);

        return areEqual;
    }
}
