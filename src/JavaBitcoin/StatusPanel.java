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

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;

/**
 * This is the status panel for the main window.  It displays information about the current
 * block chain and stored blocks in the database.
 */
public class StatusPanel extends JPanel implements AlertListener, ChainListener, ConnectionListener {

    /** Service names */
    private static final String[] serviceNames = {"Network"};

    /** Create our logger */
    private static final Logger log = LoggerFactory.getLogger(StatusPanel.class);

    /** Block status table column classes */
    private static final Class<?>[] blockColumnClasses = {
        Date.class, Integer.class, String.class, String.class};

    /** Block status table column names */
    private static final String[] blockColumnNames = {
        "Date", "Height", "Block", "Status"};

    /** Block status table column types */
    private static final int[] blockColumnTypes = {
        SizedTable.DATE, SizedTable.INTEGER, SizedTable.HASH, SizedTable.STATUS};

    /** Block status table model */
    private BlockTableModel blockTableModel;

    /** Block status table */
    private JTable blockTable;

    /** Block status scroll pane */
    private JScrollPane blockScrollPane;

    /** Alert table column classes */
    private static final Class<?>[] alertColumnClasses = {
        Integer.class, Date.class, String.class, String.class};

    /** Alert table column names */
    private static final String[] alertColumnNames = {
        "ID", "Expires", "Status", "Message"};

    /** Alert table column types */
    private static final int[] alertColumnTypes = {
        SizedTable.INTEGER, SizedTable.DATE, SizedTable.STATUS, SizedTable.MESSAGE};

    /** Alert table model */
    private AlertTableModel alertTableModel;

    /** Alert table */
    private JTable alertTable;

    /** Alert scroll pane */
    private JScrollPane alertScrollPane;

    /** Connection table column classes */
    private static final Class<?>[] connectionColumnClasses = {
        String.class, Integer.class, String.class, String.class};

    /** Connection table column names */
    private static final String[] connectionColumnNames = {
        "Address", "Version", "Subversion", "Services"};

    /** Connection table column types */
    private static final int[] connectionColumnTypes = {
        SizedTable.ADDRESS, SizedTable.INTEGER, SizedTable.SUBVERSION, SizedTable.SERVICES};

    /** Connection table model */
    private ConnectionTableModel connectionTableModel;

    /** Connection table */
    private JTable connectionTable;

    /** Connection scroll pane */
    private JScrollPane connectionScrollPane;

    /** Chain head field */
    private JLabel chainHeadField;

    /** Chain height field */
    private JLabel chainHeightField;

    /** Network difficulty field */
    private JLabel networkDifficultyField;

    /** Peer connections field */
    private JLabel peerConnectionsField;

    /**
     * Create the status panel
     */
    public StatusPanel() {
        super(new BorderLayout());
        setOpaque(true);
        setBackground(Color.WHITE);
        setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
        JPanel tablePane = new JPanel();
        tablePane.setBackground(Color.WHITE);
        //
        // Get the main window size
        //
        int frameWidth = 640;
        int frameHeight = 580;
        String frameSize = Main.properties.getProperty("window.main.size");
        if (frameSize != null) {
            int sep = frameSize.indexOf(',');
            frameWidth = Integer.parseInt(frameSize.substring(0, sep));
            frameHeight = Integer.parseInt(frameSize.substring(sep+1));
        }
        //
        // Create the alert table
        //
        int tableHeight;
        int rowHeight;
        try {
            alertTableModel = new AlertTableModel(alertColumnNames, alertColumnClasses);
            alertTable = new SizedTable(alertTableModel, alertColumnTypes);
            alertTable.setRowSorter(new TableRowSorter<TableModel>(alertTableModel));
            alertTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            tableHeight = frameHeight/8;
            rowHeight = alertTable.getRowHeight();
            tableHeight = (tableHeight/rowHeight)*rowHeight;
            alertTable.setPreferredScrollableViewportSize(new Dimension(frameWidth-60, tableHeight));
            alertScrollPane = new JScrollPane(alertTable);
            tablePane.add(Box.createGlue());
            tablePane.add(new JLabel("<html><h3>Alerts</h3></html>"));
            tablePane.add(alertScrollPane);
        } catch (BlockStoreException exc) {
            log.error("Block store exception while creating alert table", exc);
        }
        //
        // Create the connection table
        //
        connectionTableModel = new ConnectionTableModel(connectionColumnNames, connectionColumnClasses);
        connectionTable = new SizedTable(connectionTableModel, connectionColumnTypes);
        connectionTable.setRowSorter(new TableRowSorter<TableModel>(connectionTableModel));
        connectionTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        tableHeight = frameHeight/5;
        rowHeight = connectionTable.getRowHeight();
        tableHeight = (tableHeight/rowHeight)*rowHeight;
        connectionTable.setPreferredScrollableViewportSize(new Dimension(frameWidth-60, tableHeight));
        connectionScrollPane = new JScrollPane(connectionTable);
        tablePane.add(Box.createGlue());
        tablePane.add(new JLabel("<html><h3>Connections</h3></html>"));
        tablePane.add(connectionScrollPane);
        //
        // Create the block status table
        //
        try {
            blockTableModel = new BlockTableModel(blockColumnNames, blockColumnClasses);
            blockTable = new SizedTable(blockTableModel, blockColumnTypes);
            blockTable.setRowSorter(new TableRowSorter<TableModel>(blockTableModel));
            blockTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            tableHeight = frameHeight/4;
            rowHeight = blockTable.getRowHeight();
            tableHeight = (tableHeight/rowHeight)*rowHeight;
            blockTable.setPreferredScrollableViewportSize(new Dimension(frameWidth-60, tableHeight));
            blockScrollPane = new JScrollPane(blockTable);
            tablePane.add(Box.createGlue());
            tablePane.add(new JLabel("<html><h3>Recent Blocks</h3></html>"));
            tablePane.add(blockScrollPane);
            tablePane.add(Box.createGlue());
        } catch (BlockStoreException exc) {
            log.error("Block store exception while creating block status table", exc);
        }
        //
        // Create the status pane containing the chain head, chain height, network difficulty,
        // and number of peer connections
        //
        chainHeadField = new JLabel();
        JPanel chainHeadPane = new JPanel();
        chainHeadPane.add(Box.createGlue());
        chainHeadPane.add(chainHeadField);
        chainHeadPane.add(Box.createGlue());

        chainHeightField = new JLabel();
        JPanel chainHeightPane = new JPanel();
        chainHeightPane.add(Box.createGlue());
        chainHeightPane.add(chainHeightField);
        chainHeightPane.add(Box.createGlue());

        networkDifficultyField = new JLabel();
        JPanel networkDifficultyPane = new JPanel();
        networkDifficultyPane.add(Box.createGlue());
        networkDifficultyPane.add(networkDifficultyField);
        networkDifficultyPane.add(Box.createGlue());

        peerConnectionsField = new JLabel();
        JPanel peerConnectionsPane = new JPanel();
        peerConnectionsPane.add(Box.createGlue());
        peerConnectionsPane.add(peerConnectionsField);
        peerConnectionsPane.add(Box.createGlue());

        JPanel statusPane = new JPanel();
        statusPane.setLayout(new BoxLayout(statusPane, BoxLayout.Y_AXIS));
        statusPane.setOpaque(true);
        statusPane.setBackground(Color.WHITE);

        statusPane.add(chainHeadPane);
        statusPane.add(chainHeightPane);
        statusPane.add(networkDifficultyPane);
        statusPane.add(peerConnectionsPane);
        statusPane.add(Box.createVerticalStrut(20));
        //
        // Set up the content pane
        //
        add(statusPane, BorderLayout.NORTH);
        add(tablePane, BorderLayout.CENTER);
        //
        // Register for chain notifications
        //
        Parameters.blockChain.addListener((ChainListener)this);
        //
        // Register for connection notifications
        //
        Parameters.networkListener.addListener((ConnectionListener)this);
        //
        // Register for alert notifications
        //
        Parameters.networkListener.addListener((AlertListener)this);
        //
        // Get the initiali connections and update the status
        //
        connectionTableModel.updateConnections();
        updateStatus();
    }

    /**
     * Notification when a new block is stored in the database
     *
     * @param       storedBlock     The stored block
     */
    @Override
    public void blockStored(StoredBlock storedBlock) {
        blockTableModel.blockStored(storedBlock);
    }

    /**
     * Notification when a block status is changed
     *
     * @param       storedBlock     The stored block
     */
    @Override
    public void blockUpdated(StoredBlock storedBlock) {
        blockTableModel.blockStored(storedBlock);
    }

    /**
     * Notification when the chain is updated
     */
    @Override
    public void chainUpdated() {
        javax.swing.SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                updateStatus();
            }
        });
    }

    /**
     * Notification when a connection starts
     *
     * @param       peer            Remote peer
     * @param       count           Connection count
     */
    @Override
    public void connectionStarted(Peer peer, int count) {
        connectionTableModel.addConnection(peer);
        javax.swing.SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                updateStatus();
            }
        });
    }

    /**
     * Notification when a connection ends
     *
     * @param       peer            Remote peer
     * @param       count           Connection count
     */
    @Override
    public void connectionEnded(Peer peer, int count) {
        connectionTableModel.removeConnection(peer);
        javax.swing.SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                updateStatus();
            }
        });
    }

    /**
     * Notification when an alert is received
     *
     * @param       alert           Alert
     */
    @Override
    public void alertReceived(Alert alert) {
        alertTableModel.addAlert(alert);
    }

    /**
     * Update the status fields
     */
    private void updateStatus() {
        Sha256Hash chainHead = Parameters.blockStore.getChainHead();
        chainHeadField.setText(String.format("<html><b>Chain head: %s</b></html>",
                                             chainHead.toString()));
        int chainHeight = Parameters.blockStore.getChainHeight();
        chainHeightField.setText(String.format("<html><b>Chain height: %d</b></html>",
                                               chainHeight));
        BigInteger targetDifficulty = Parameters.blockStore.getTargetDifficulty();
        BigInteger networkDifficulty = Parameters.PROOF_OF_WORK_LIMIT.divide(targetDifficulty);
        String displayDifficulty = Utils.numberToShortString(networkDifficulty);
        networkDifficultyField.setText(String.format("<html><b>Network difficulty: %s</b></html>",
                                                     displayDifficulty));
        peerConnectionsField.setText(String.format("<html><b>Peer connections: %d</b></html>",
                                                   connectionTable.getRowCount()));
    }

    /**
     * Comparator to sort the block status list from newest to oldest
     */
    private class BlockStatusComparator implements Comparator<BlockStatus> {

        /**
         * Creates the comparator
         */
        public BlockStatusComparator() {
        }

        /**
         * Compares two block status objects in descending order
         *
         * @param       o1          The first status object
         * @param       o2          The second status object
         * @return      -1 if less than, 0 if equal to, 1 if greater than
         */
        @Override
        public int compare(BlockStatus o1, BlockStatus o2) {
            long t1 = o1.getTimeStamp();
            long t2 = o2.getTimeStamp();
            return (t1==t2 ? 0 : (t1>t2 ? -1 : 1));
        }
    }

    /**
     * Table model for the block status table
     */
    private class BlockTableModel extends AbstractTableModel {

        /** Column names */
        private String[] columnNames;

        /** Column classes */
        private Class<?>[] columnClasses;

        /** Block status list */
        private BlockStatus[] blocks;

        /** Block hash map */
        private Map<Sha256Hash, BlockStatus> blockMap = new HashMap<>(50);

        /** Block height map */
        private Map<Integer, BlockStatus> heightMap = new HashMap<>(50);

        /** Table refresh pending */
        private boolean refreshPending;

        /**
         * Create the table model
         *
         * @param       columnName          Column names
         * @param       columnClasses       Column classes
         * @throws      BlockStoreException Unable to get block status from database
         */
        public BlockTableModel(String[] columnNames, Class<?>[] columnClasses) throws BlockStoreException {
            super();
            this.columnNames = columnNames;
            this.columnClasses = columnClasses;
            //
            // Get the current block status and build an array sorted by descending timestamp
            //
            blocks = (BlockStatus[])Parameters.blockStore.getBlockStatus(150).toArray(new BlockStatus[0]);
            Arrays.sort(blocks, new BlockStatusComparator());
            for (BlockStatus block : blocks) {
                blockMap.put(block.getHash(), block);
                if (block.isOnChain())
                    heightMap.put(Integer.valueOf(block.getHeight()), block);
            }
        }

        /**
         * Get the number of columns in the table
         *
         * @return                  The number of columns
         */
        @Override
        public int getColumnCount() {
            return columnNames.length;
        }

        /**
         * Get the column class
         *
         * @param       column      Column number
         * @return                  The column class
         */
        @Override
        public Class<?> getColumnClass(int column) {
            return columnClasses[column];
        }

        /**
         * Get the column name
         *
         * @param       column      Column number
         * @return                  Column name
         */
        @Override
        public String getColumnName(int column) {
            return columnNames[column];
        }

        /**
         * Get the number of rows in the table
         *
         * @return                  The number of rows
         */
        @Override
        public int getRowCount() {
            return blocks.length;
        }

        /**
         * Get the value for a cell
         *
         * @param       row         Row number
         * @param       column      Column number
         * @return                  Returns the object associated with the cell
         */
        @Override
        public Object getValueAt(int row, int column) {
            if (row >= blocks.length || column >= columnNames.length)
                return "";

            Object value;
            BlockStatus status;
            synchronized(Parameters.lock) {
                status = blocks[row];
            }
            //
            // Get the value for the requested cell
            //
            switch (column) {
                case 0:                             // Date
                    value = new Date(status.getTimeStamp()*1000);
                    break;
                case 1:                             // Height
                    value = Integer.valueOf(status.isOnChain() ? status.getHeight() : 0);
                    break;
                case 2:                             // Block hash
                    value = status.getHash().toString();
                    break;
                case 3:                             // Block status
                    if (status.isOnChain())
                        value = "On Chain";
                    else if (status.isOnHold())
                        value = "Held";
                    else
                        value = "Ready";
                    break;
                default:
                    throw new IndexOutOfBoundsException("Table column "+column+" is not valid");
            }
            return value;
        }

        /**
        * Notification when a new block is stored in the database
        *
        * @param       storedBlock      The stored block
        */
        public void blockStored(StoredBlock storedBlock) {
            Sha256Hash blockHash = storedBlock.getHash();
            Integer blockHeight = Integer.valueOf(storedBlock.getHeight());
            synchronized(Parameters.lock) {
                //
                // Update the block status
                //
                BlockStatus blockStatus = blockMap.get(blockHash);
                if (blockStatus == null) {
                    blockStatus = new BlockStatus(blockHash, storedBlock.getBlock().getTimeStamp(),
                                                  storedBlock.getHeight(), storedBlock.isOnChain(),
                                                  storedBlock.isOnHold());
                    BlockStatus[] newBlocks = new BlockStatus[blocks.length+1];
                    System.arraycopy(blocks, 0, newBlocks, 0, blocks.length);
                    newBlocks[blocks.length] = blockStatus;
                    Arrays.sort(newBlocks, new BlockStatusComparator());
                    blocks = newBlocks;
                    blockMap.put(blockHash, blockStatus);
                } else {
                    blockStatus.setHeight(storedBlock.getHeight());
                    blockStatus.setChain(storedBlock.isOnChain());
                    blockStatus.setHold(storedBlock.isOnHold());
                }
                //
                // Check for an existing block at the same height.  This happens
                // when the chain is reorganized and blocks are removed from the chain.
                //
                if (storedBlock.isOnChain()) {
                    BlockStatus chkStatus = heightMap.get(blockHeight);
                    if (chkStatus == null) {
                        heightMap.put(blockHeight, blockStatus);
                    } else if (!chkStatus.getHash().equals(blockHash)) {
                        chkStatus.setChain(false);
                        chkStatus.setHeight(0);
                        heightMap.put(blockHeight, blockStatus);
                    }
                }
            }
            //
            // Update the table on the GUI thread
            //
            if (!refreshPending) {
                refreshPending = true;
                javax.swing.SwingUtilities.invokeLater(new Runnable() {
                    @Override
                    public void run() {
                        fireTableDataChanged();
                        refreshPending = false;
                    }
                });
            }
        }
    }

    /**
     * Table model for the alert table
     */
    private class AlertTableModel extends AbstractTableModel {

        /** Column names */
        private String[] columnNames;

        /** Column classes */
        private Class<?>[] columnClasses;

        /** Alert list */
        private List<Alert> alertList;

        /** Table refresh pending */
        private boolean refreshPending = false;

        /**
         * Create the table model
         *
         * @param       columnName          Column names
         * @param       columnClasses       Column classes
         * @throws      BlockStoreException Unable to get alerts from the database
         */
        public AlertTableModel(String[] columnNames, Class<?>[] columnClasses) throws BlockStoreException {
            super();
            this.columnNames = columnNames;
            this.columnClasses = columnClasses;
            //
            // Get the current alert list
            //
            alertList = Parameters.blockStore.getAlerts();
        }

        /**
         * Get the number of columns in the table
         *
         * @return                  The number of columns
         */
        @Override
        public int getColumnCount() {
            return columnNames.length;
        }

        /**
         * Get the column class
         *
         * @param       column      Column number
         * @return                  The column class
         */
        @Override
        public Class<?> getColumnClass(int column) {
            return columnClasses[column];
        }

        /**
         * Get the column name
         *
         * @param       column      Column number
         * @return                  Column name
         */
        @Override
        public String getColumnName(int column) {
            return columnNames[column];
        }

        /**
         * Get the number of rows in the table
         *
         * @return                  The number of rows
         */
        @Override
        public int getRowCount() {
            return alertList.size();
        }

        /**
         * Get the value for a cell
         *
         * @param       row         Row number
         * @param       column      Column number
         * @return                  Returns the object associated with the cell
         */
        @Override
        public Object getValueAt(int row, int column) {
            Object value = null;
            if (row > alertList.size())
                return "";
            //
            // The database returns the alerts sorted by the alert ID.
            // We want to show the most recent alert first, so process the
            // list in reverse order.
            //
            Alert alert = alertList.get(alertList.size()-1-row);
            switch (column) {
                case 0:                     // Alert ID
                    value = Integer.valueOf(alert.getID());
                    break;

                case 1:                     // Expiration date
                    value = new Date(alert.getExpireTime()*1000);
                    break;

                case 2:                     // Status
                    if (alert.isCanceled())
                        value = "Canceled";
                    else if (alert.getExpireTime() < System.currentTimeMillis()/1000)
                        value = "Expired";
                    else
                        value = "";
                    break;

                case 3:                     // Alert message
                    value = alert.getMessage();
                    break;
            }
            return value;
        }

        /**
         * Add a new alert to the table
         *
         * @param       alert           Alert
         */
        public void addAlert(Alert alert) {
            alertList.add(alert);
            //
            // Update the table on the GUI thread
            //
            if (!refreshPending) {
                refreshPending = true;
                javax.swing.SwingUtilities.invokeLater(new Runnable() {
                    @Override
                    public void run() {
                        fireTableDataChanged();
                        refreshPending = false;
                    }
                });
            }
        }
    }

    /**
     * Table model for the connections table
     */
    private class ConnectionTableModel extends AbstractTableModel {

        /** Column names */
        private String[] columnNames;

        /** Column classes */
        private Class<?>[] columnClasses;

        /** Connection list */
        private List<Peer> connectionList = new LinkedList<>();

        /**
         * Create the table model
         *
         * @param       columnName          Column names
         * @param       columnClasses       Column classes
         */
        public ConnectionTableModel(String[] columnNames, Class<?>[] columnClasses) {
            super();
            this.columnNames = columnNames;
            this.columnClasses = columnClasses;
        }

        /**
         * Get the number of columns in the table
         *
         * @return                  The number of columns
         */
        @Override
        public int getColumnCount() {
            return columnNames.length;
        }

        /**
         * Get the column class
         *
         * @param       column      Column number
         * @return                  The column class
         */
        @Override
        public Class<?> getColumnClass(int column) {
            return columnClasses[column];
        }

        /**
         * Get the column name
         *
         * @param       column      Column number
         * @return                  Column name
         */
        @Override
        public String getColumnName(int column) {
            return columnNames[column];
        }

        /**
         * Get the number of rows in the table
         *
         * @return                  The number of rows
         */
        @Override
        public int getRowCount() {
            return connectionList.size();
        }

        /**
         * Get the value for a cell
         *
         * @param       row         Row number
         * @param       column      Column number
         * @return                  Returns the object associated with the cell
         */
        @Override
        public Object getValueAt(int row, int column) {
            Object value = null;
            if (row >= connectionList.size() || column >= columnClasses.length)
                return "";
            Peer peer = connectionList.get(row);
            switch (column) {
                case 0:                         // IP address
                    value = peer.getAddress().toString();
                    break;

                case 1:                         // Protocol version
                    value = Integer.valueOf(peer.getVersion());
                    break;

                case 2:                         // Subversion
                    value = peer.getUserAgent();
                    break;

                case 3:                         // Services
                    long services = peer.getServices();
                    StringBuilder serviceString = new StringBuilder(32);
                    for (int i=0; i<serviceNames.length; i++) {
                        if ((services & (1<<i)) != 0)
                            serviceString.append(serviceNames[i]);
                    }
                    value = serviceString.toString();
                    break;
            }
            return value;
        }

        /**
         * Update the connection list
         */
        public void updateConnections() {
            List<Peer> connections = Parameters.networkListener.getConnections();
            for (Peer peer : connections) {
                if (!connectionList.contains(peer))
                    connectionList.add(peer);
            }
        }

        /**
         * Add a new connection
         *
         * @param       peer            Peer
         */
        public void addConnection(Peer peer) {
            ConnectionUpdate updateTask = new ConnectionUpdate(connectionList, peer, true);
            javax.swing.SwingUtilities.invokeLater(updateTask);
        }

        /**
         * Remove a connection
         *
         * @param       peer            Peer
         */
        public void removeConnection(Peer peer) {
            ConnectionUpdate updateTask = new ConnectionUpdate(connectionList, peer, false);
            javax.swing.SwingUtilities.invokeLater(updateTask);
        }
    }

    /**
     * Update the connection table on the GUI thread to avoid table repaint errors
     * for connections that begin and end immediately
     */
    private class ConnectionUpdate implements Runnable {

        /** Update action */
        private boolean addConnection;

        /** Peer */
        private Peer peer;

        /** Connection list */
        private List<Peer> connectionList;

        /**
         * Creates a new connection update
         *
         * @param       connectionList      Connection list
         * @param       peer                Peer connection to add or remove
         * @param       addConnection       TRUE to add a connection, FALSE to remove a connection
         */
        public ConnectionUpdate(List<Peer> connectionList, Peer peer, boolean addConnection) {
            this.connectionList = connectionList;
            this.peer = peer;
            this.addConnection = addConnection;
        }

        /**
         * Process the event
         */
        @Override
        public void run() {
            //
            // Add or remove the peer connection
            //
            if (addConnection) {
                if (!connectionList.contains(peer))
                    connectionList.add(peer);
            } else {
                connectionList.remove(peer);
            }
            //
            // Update the table
            //
            connectionTableModel.fireTableDataChanged();
        }
    }
}
