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
 * A chain listener register with the block chain for notifications when a
 * new block is stored in a database or the chain head is updated.
 */
public interface ChainListener {

    /**
     * Notifies the listener when a new block is stored in the database
     *
     * @param       storedBlock     The stored block
     */
    public void blockStored(StoredBlock storedBlock);

    /**
     * Notifies the listener when the block status changes
     *
     * @param       storedBlock     The stored block
     */
    public void blockUpdated(StoredBlock storedBlock);

    /**
     * Notifies the listener when the chain head is updated
     */
    public void chainUpdated();
}
