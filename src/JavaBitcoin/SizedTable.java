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

import java.util.Date;

import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;

/**
 * The SizedTable class is a JTable with column sizes based on the column data types
 */
public final class SizedTable extends JTable {

    /** Date column */
    public static final int DATE = 1;

    /** Integer column */
    public static final int INTEGER = 2;

    /** Block hash column */
    public static final int HASH = 3;

    /** Status column */
    public static final int STATUS = 4;

    /** Message column */
    public static final int MESSAGE = 5;

    /** IP address column */
    public static final int ADDRESS = 6;

    /** Subversion column */
    public static final int SUBVERSION = 7;

    /** Services column */
    public static final int SERVICES = 8;

    /**
     * Create a new sized table
     *
     * @param       tableModel      The table model
     * @param       columnTypes     Array of column types
     */
    public SizedTable(TableModel tableModel, int[] columnTypes) {

        //
        // Create the table
        //
        super(tableModel);

        //
        // Set the cell renderers and column widths
        //
        Component component;
        TableCellRenderer renderer;
        TableColumn column;
        TableColumnModel columnModel = getColumnModel();
        TableCellRenderer headRenderer = getTableHeader().getDefaultRenderer();
        if (headRenderer instanceof DefaultTableCellRenderer) {
            DefaultTableCellRenderer defaultRenderer = (DefaultTableCellRenderer)headRenderer;
            defaultRenderer.setHorizontalAlignment(JLabel.CENTER);
        }

        int columnCount = tableModel.getColumnCount();
        if (columnCount > columnTypes.length)
            throw new IllegalArgumentException("More columns than column types");

        for (int i=0; i<columnCount; i++) {
            Object value = null;
            column = columnModel.getColumn(i);
            switch (columnTypes[i]) {
                case DATE:
                    column.setCellRenderer(new DateRenderer());
                    value = new Date();
                    break;

                case INTEGER:                                       // 6 digits
                    value = "mmmmmn";
                    break;

                case HASH:                                          // 64 characters
                    column.setCellRenderer(new StringRenderer(JLabel.RIGHT));
                    value = "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn";
                    break;

                case STATUS:                                        // 16 character
                    column.setCellRenderer(new StringRenderer(JLabel.CENTER));
                    value = "Mmmmmmmmmmmmmmmm";
                    break;

                case MESSAGE:                                       // 80 characters
                    value = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
                    break;

                case ADDRESS:                                       // IP address
                    column.setCellRenderer(new StringRenderer(JLabel.RIGHT));
                    value = "nnnn:nnnn:nnnn:nnnn:nnnn:nnnn:nnnn:nnnn[nnnn]";
                    break;

                case SUBVERSION:                                    // 32 characters
                    column.setCellRenderer(new StringRenderer(JLabel.CENTER));
                    value = "Mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm";
                    break;

                case SERVICES:                                      // 32 characters
                    column.setCellRenderer(new StringRenderer(JLabel.CENTER));
                    value = "Mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm";
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported column type "+columnTypes[i]);
            }

            component = headRenderer.getTableCellRendererComponent(this, tableModel.getColumnName(i),
                                                                   false, false, 0, i);
            int headWidth = component.getPreferredSize().width;
            renderer = column.getCellRenderer();
            if (renderer == null)
                renderer = getDefaultRenderer(tableModel.getColumnClass(i));
            component = renderer.getTableCellRendererComponent(this, value, false, false, 0, i);
            int cellWidth = component.getPreferredSize().width;
            column.setPreferredWidth(Math.max(headWidth+5, cellWidth+5));
        }

        //
        // Resize all column proportionally
        //
        setAutoResizeMode(AUTO_RESIZE_ALL_COLUMNS);
    }
}
