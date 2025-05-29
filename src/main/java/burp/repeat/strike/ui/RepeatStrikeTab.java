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
import static burp.repeat.strike.RepeatStrikeExtension.*;
import static burp.repeat.strike.ui.ScanChecksMenus.*;
import static burp.repeat.strike.utils.Utils.alert;
import static burp.repeat.strike.utils.Utils.prompt;
import static java.awt.event.HierarchyEvent.SHOWING_CHANGED;

public class RepeatStrikeTab extends JTabbedPane {
    public final JButton runSavedScanChecksButton;
    public final JButton saveLastScanCheckButton;
    public final SavedScanChecksEditor scanChecksEditor = new SavedScanChecksEditor();
    private final HttpRequestEditor httpRequestEditor;
    private final HttpResponseEditor httpResponseEditor;
    private final JButton generateScanCheckButton;
    private final JButton clearButton;
    private final java.util.List<HttpRequestResponse> requestResponseList = new ArrayList<>();
    private final RequestTableModel tableModel = new RequestTableModel(requestResponseList);
    private final JTable table = new JTable(tableModel);
    public void clearQueue() {
        repeatStrikePanel.resetInstructions();
        requestResponseList.clear();
        httpRequestEditor.setRequest(HttpRequest.httpRequest(""));
        httpResponseEditor.setResponse(HttpResponse.httpResponse());
        clearButton.setEnabled(false);
        generateScanCheckButton.setEnabled(false);
    }

    public RepeatStrikeTab(UserInterface userInterface) {
        super();
        JPanel panel = new JPanel(new BorderLayout());
        this.add("Requests/responses queue", panel);
        this.add("Saved scan checks", scanChecksEditor);
        this.httpRequestEditor = userInterface.createHttpRequestEditor(READ_ONLY);
        this.httpResponseEditor = userInterface.createHttpResponseEditor(READ_ONLY);
        this.clearButton = new JButton("Clear");
        runSavedScanChecksButton = new JButton("Run scan checks on proxy history");
        runSavedScanChecksButton.setEnabled(ScanCheckUtils.getSavedCustomScanChecks().keySet().isEmpty());
        runSavedScanChecksButton.addActionListener(e -> {
            JSONObject scanChecksJSON = ScanCheckUtils.getSavedCustomScanChecks();
            JPopupMenu savedScanChecksPopupMenu;
            if(scanChecksJSON.keySet().isEmpty()) {
                savedScanChecksPopupMenu = new JPopupMenu();
                savedScanChecksPopupMenu.add(new JMenuItem("No scan checks are saved."));
            } else {
                savedScanChecksPopupMenu = ScanChecksMenus.buildScanCheckMenu(scanChecksJSON);
            }

            savedScanChecksPopupMenu.show(runSavedScanChecksButton, 0, runSavedScanChecksButton.getHeight());
        });
        this.generateScanCheckButton = new JButton("Generate scan check");
        this.generateScanCheckButton.setBackground(Color.decode("#d86633"));
        this.generateScanCheckButton.setForeground(Color.white);
        this.generateScanCheckButton.addActionListener(e -> {
            JPopupMenu scanPopupMenu = new JPopupMenu();
            scanPopupMenu.setEnabled(!requestHistory.isEmpty());
            scanPopupMenu.add(buildRunJavaScanMenu());
            scanPopupMenu.add(buildRunRegexScanMenu());
            scanPopupMenu.add(buildRunDiffingScanMenu());
            scanPopupMenu.show(generateScanCheckButton, 0, generateScanCheckButton.getHeight());
        });
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int viewRow = table.getSelectedRow();
                if (viewRow >= 0) {
                    int modelRow = table.convertRowIndexToModel(viewRow);
                    if (modelRow >= 0 && modelRow < requestResponseList.size()) {
                        HttpRequestResponse selected = requestResponseList.get(modelRow);
                        httpRequestEditor.setRequest(selected.request());
                        httpResponseEditor.setResponse(selected.response());
                    }
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
                    clearQueue();
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
        splitPane.setResizeWeight(0.5);
        splitPane.add(httpRequestEditor.uiComponent(), JSplitPane.LEFT);
        splitPane.add(httpResponseEditor.uiComponent(), JSplitPane.RIGHT);
        panel.add(splitPane, BorderLayout.CENTER);
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 10));

        clearButton.setEnabled(false);
        clearButton.addActionListener(e -> {
            tableModel.clear();
            clearButton.setEnabled(false);
            generateScanCheckButton.setEnabled(false);
            httpRequestEditor.setRequest(HttpRequest.httpRequest(""));
            httpResponseEditor.setResponse(HttpResponse.httpResponse());
            Utils.resetHistory(false);
        });
        buttonPanel.add(clearButton);
        saveLastScanCheckButton = new JButton("Save last scan check");
        saveLastScanCheckButton.setEnabled(false);
        saveLastScanCheckButton.addActionListener(e -> {
            JSONObject scanChecksJSON = ScanCheckUtils.getSavedCustomScanChecks();
            if(lastScanCheckRan == null || lastScanCheckRan.isEmpty()) {
                JPopupMenu scanPopupMenu = new JPopupMenu();
                scanPopupMenu.add(new JMenuItem("You need to generate a scan check first."));
                scanPopupMenu.show(saveLastScanCheckButton, 0, saveLastScanCheckButton.getHeight());
                return;
            }
            if(lastScanCheckRan != null) {
                String scanCheckName = prompt(null, "Save Last Scan", "Enter the name of your scan check:");
                if(!ScanCheckUtils.validateScanCheckName(scanCheckName)) {
                    alert("Invalid scan check name.");
                    return;
                }
                ScanCheckUtils.addCustomScanCheck(scanCheckName, lastScanCheckRan, scanChecksJSON);
                lastScanCheckRan = null;
                saveLastScanCheckButton.setEnabled(false);
                repeatStrikePanel.setStatus("Idle", false);
            }
        });
        buttonPanel.add(saveLastScanCheckButton);
        generateScanCheckButton.setEnabled(false);
        buttonPanel.add(runSavedScanChecksButton);
        buttonPanel.add(generateScanCheckButton);
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
            generateScanCheckButton.setEnabled(true);
            repeatStrikePanel.setInstructions("You now have requests and responses in the queue. Click the \"Generate scan check\" button at the bottom right to start.");
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