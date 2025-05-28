package burp.repeat.strike.ui;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.repeat.strike.utils.ScanCheckUtils;
import burp.repeat.strike.utils.Utils;
import org.json.JSONObject;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.event.HierarchyEvent;
import java.awt.event.HierarchyListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

import static burp.api.montoya.ui.editor.EditorOptions.READ_ONLY;
import static burp.repeat.strike.RepeatStrikeExtension.requestHistory;
import static burp.repeat.strike.RepeatStrikeExtension.responseHistory;
import static burp.repeat.strike.ui.ScanChecksMenus.*;
import static java.awt.event.HierarchyEvent.SHOWING_CHANGED;

public class RepeatStrikeTab extends JTabbedPane {
    private final HttpRequestEditor httpRequestEditor;
    private final HttpResponseEditor httpResponseEditor;
    private final JButton operationsButton;
    private final JButton clearButton;

    private final java.util.List<HttpRequestResponse> requestResponseList = new ArrayList<>();
    private final RequestTableModel tableModel = new RequestTableModel(requestResponseList);
    private final JTable table = new JTable(tableModel);
    public final SavedScanChecksEditor scanChecksEditor = new SavedScanChecksEditor();

    public RepeatStrikeTab(UserInterface userInterface) {
        super();
        JPanel panel = new JPanel(new BorderLayout());
        this.add("Requests/responses queue", panel);
        this.add("Saved scan checks", scanChecksEditor);
        this.httpRequestEditor = userInterface.createHttpRequestEditor(READ_ONLY);
        this.httpResponseEditor = userInterface.createHttpResponseEditor(READ_ONLY);
        this.clearButton = new JButton("Clear");
        this.operationsButton = new JButton("Operations");
        this.operationsButton.setBackground(Color.decode("#d86633"));
        this.operationsButton.setForeground(Color.white);
        JPopupMenu operationsPopupMenu = new JPopupMenu();
        this.operationsButton.addActionListener(e -> {
            operationsPopupMenu.removeAll();
            JSONObject scanChecksJSON = ScanCheckUtils.getSavedCustomScanChecks();
            JMenu scanMenu = new JMenu("Scan " + "(" + requestHistory.size() + ")");
            scanMenu.setEnabled(!requestHistory.isEmpty());
            scanMenu.add(buildRunJavaScanMenu());
            scanMenu.add(buildRunRegexScanMenu());
            scanMenu.add(buildRunDiffingScanMenu());
            operationsPopupMenu.add(scanMenu);
            operationsPopupMenu.add(ScanChecksMenus.buildScanCheckMenu(scanChecksJSON));
            operationsPopupMenu.add(ScanChecksMenus.buildSaveLastScanCheckMenu(scanChecksJSON));
            operationsPopupMenu.add(buildResetMenu());
            operationsPopupMenu.add(buildDeleteAllScanChecksMenu(scanChecksJSON));
            operationsPopupMenu.show(operationsButton, 0, operationsButton.getHeight());
        });
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = table.getSelectedRow();
                if (selectedRow >= 0) {
                    HttpRequestResponse selected = requestResponseList.get(selectedRow);
                    httpRequestEditor.setRequest(selected.request());
                    httpResponseEditor.setResponse(selected.response());
                }
            }
        });

        int[] selectedRow = new int[1];
        JPopupMenu jTablePopupMenu = new JPopupMenu();
        JMenuItem removeMenuItem = new JMenuItem("Remove");
        removeMenuItem.addActionListener(e -> {
            int row = selectedRow[0];
            if (row >= 0 && row < tableModel.getRowCount()) {
                tableModel.removeRow(row);
                requestHistory.remove(row);
                responseHistory.remove(row);
                if(requestHistory.isEmpty()) {
                    clearButton.setEnabled(false);
                    operationsButton.setEnabled(false);
                    httpRequestEditor.setRequest(HttpRequest.httpRequest(""));
                    httpResponseEditor.setResponse(HttpResponse.httpResponse());
                }
            }
        });
        jTablePopupMenu.add(removeMenuItem);
        table.addMouseListener(new MouseAdapter() {
            private void showPopup(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int row = table.rowAtPoint(e.getPoint());

                    if (!table.isRowSelected(row)) {
                        table.setRowSelectionInterval(row, row);
                    }
                    selectedRow[0] = row;
                    jTablePopupMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }

            @Override
            public void mousePressed(MouseEvent e) {
                showPopup(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                showPopup(e);
            }
        });

        JScrollPane scrollPane = new JScrollPane(table);
        panel.add(scrollPane, BorderLayout.NORTH);
        JSplitPane splitPane = new JSplitPane();
        splitPane.add(httpRequestEditor.uiComponent(), JSplitPane.LEFT);
        splitPane.add(httpResponseEditor.uiComponent(), JSplitPane.RIGHT);
        panel.add(splitPane, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 10));

        clearButton.setEnabled(false);
        clearButton.addActionListener(e -> {
            tableModel.clear();
            clearButton.setEnabled(false);
            operationsButton.setEnabled(false);
            httpRequestEditor.setRequest(HttpRequest.httpRequest(""));
            httpResponseEditor.setResponse(HttpResponse.httpResponse());
            requestResponseList.clear();
            Utils.resetHistory(false);

        });
        buttonPanel.add(clearButton);

        buttonPanel.add(new JSeparator(VERTICAL));

        operationsButton.setEnabled(false);
        buttonPanel.add(operationsButton);
        panel.add(buttonPanel, BorderLayout.SOUTH);
        addHierarchyListener(new HierarchyListener() {
            @Override
            public void hierarchyChanged(HierarchyEvent e) {
                if (e.getChangeFlags() == SHOWING_CHANGED && e.getComponent().isShowing()) {
                    splitPane.setDividerLocation(0.5);
                    removeHierarchyListener(this);
                }
            }
        });
    }

    public void addRequestResponse(HttpRequestResponse requestResponse) {
        SwingUtilities.invokeLater(() -> {
            requestResponseList.add(requestResponse);
            tableModel.fireTableRowsInserted(requestResponseList.size() - 1, requestResponseList.size() - 1);

            httpRequestEditor.setRequest(requestResponse.request());

            var response = requestResponse.hasResponse() ? requestResponse.response() : HttpResponse.httpResponse();
            httpResponseEditor.setResponse(response);
            int rowCount = table.getRowCount();
            if (rowCount > 0) {
                table.setRowSelectionInterval(rowCount - 1, rowCount - 1);
                table.scrollRectToVisible(table.getCellRect(rowCount - 1, 0, true));
            }
            clearButton.setEnabled(true);
            operationsButton.setEnabled(true);
        });
    }

    static class RequestTableModel extends AbstractTableModel {
        private final List<HttpRequestResponse> data;
        private final String[] columns = { "Method", "URL", "Status" };

        public RequestTableModel(java.util.List<HttpRequestResponse> data) {
            this.data = data;
        }

        public void clear() {
            data.clear();
            fireTableDataChanged();
        }

        public void removeRow(int rowIndex) {
            data.remove(rowIndex);
            fireTableRowsDeleted(rowIndex, rowIndex);
        }

        @Override
        public int getRowCount() {
            return data.size();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int column) {
            return columns[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            HttpRequestResponse entry = data.get(rowIndex);
            switch (columnIndex) {
                case 0: return entry.request().method();
                case 1: return entry.request().url();
                case 2: return entry.response() != null ? entry.response().statusCode() : "";
                default: return "";
            }
        }
    }
}