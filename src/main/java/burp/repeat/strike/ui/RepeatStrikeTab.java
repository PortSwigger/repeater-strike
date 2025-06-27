package burp.repeat.strike.ui;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.repeat.strike.utils.StrikeRulesUtils;
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
import static burp.repeat.strike.ui.StrikeRuleMenus.*;
import static java.awt.event.HierarchyEvent.SHOWING_CHANGED;

public class RepeatStrikeTab extends JTabbedPane {
    public final String wordListWarning = "Warning you are using the word list, this will affect the AI's responses.";
    public final JButton runSavedStrikeRuleButton;
    public final SavedStrikeRulesEditor strikeRuleEditor = new SavedStrikeRulesEditor();
    private final HttpRequestEditor httpRequestEditor;
    private final HttpResponseEditor httpResponseEditor;
    private final JButton generateStrikeRuleButton;
    private final JButton clearButton;
    private final java.util.List<HttpRequestResponse> requestResponseList = new ArrayList<>();
    private final RequestTableModel tableModel = new RequestTableModel(requestResponseList);
    private final JTable table = new JTable(tableModel);
    private final JTextArea wordListTextArea = new JTextArea();
    public void clearQueue() {
        repeatStrikePanel.resetInstructions();
        requestResponseList.clear();
        httpRequestEditor.setRequest(HttpRequest.httpRequest(""));
        httpResponseEditor.setResponse(HttpResponse.httpResponse());
        clearButton.setEnabled(false);
        generateStrikeRuleButton.setEnabled(false);
        repeatStrikePanel.setStatus("Idle", false);
        Utils.resetHistory(false);
    }

    public String[] getWordList() {
        String text = wordListTextArea.getText();
        if(text == null || text.isEmpty()) {
            return new String[0];
        }
        return text.split("\n");
    }

    public void changeTabColour(String title, Color colour) {
        for(int i = 0; i < getTabCount(); i++) {
            if(this.getTitleAt(i).equals(title)) {
                this.setForegroundAt(i, colour);
                return;
            }
        }
    }

    public JPanel buildWordListPanel() {
        String savedWordList = api.persistence().extensionData().getString("wordList");
        if(savedWordList != null && !savedWordList.isEmpty()) {
            wordListTextArea.setText(savedWordList);
        }
        JPanel wordListPanel = new JPanel(new BorderLayout());
        JButton populateWordListButton = new JButton("Populate with default word list");
        String[] defaultValues = new String[]{"admin", "administrator", "carlos", "wiener", "peter"};
        populateWordListButton.addActionListener(e -> {
            wordListTextArea.setText(String.join("\n", defaultValues));
            saveWordList();
        });
        JPanel buttonPanel = new JPanel();
        JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(e -> {
            wordListTextArea.setText("");
            saveWordList();
        });
        buttonPanel.add(clearButton);
        JButton saveButton = new JButton("Save");
        saveButton.addActionListener(e -> {
            saveWordList();
        });
        buttonPanel.add(populateWordListButton);
        buttonPanel.add(saveButton);
        JScrollPane wordListScrollPane = new JScrollPane(wordListTextArea);
        wordListPanel.add(buttonPanel, BorderLayout.NORTH);
        wordListPanel.add(wordListScrollPane, BorderLayout.CENTER);
        return wordListPanel;
    }

    public void saveWordList() {
        api.persistence().extensionData().setString("wordList", String.join("\n", wordListTextArea.getText()));
        if(wordListTextArea.getText().isEmpty()) {
            changeTabColour("Word list", null);
            repeatStrikePanel.setWordListWarning("");
        } else {
            changeTabColour("Word list", Color.decode("#00d390"));
            repeatStrikePanel.setWordListWarning(wordListWarning);
        }
    }

    public RepeatStrikeTab(UserInterface userInterface) {
        super();
        JPanel panel = new JPanel(new BorderLayout());
        this.add("Requests/responses queue", panel);
        this.add("Saved Strike Rules", strikeRuleEditor);
        this.add("Word list", this.buildWordListPanel());

        if(getWordList().length > 0) {
            this.changeTabColour("Word list", Color.decode("#00d390"));
        }
        this.httpRequestEditor = userInterface.createHttpRequestEditor(READ_ONLY);
        this.httpResponseEditor = userInterface.createHttpResponseEditor(READ_ONLY);
        this.clearButton = new JButton("Clear");
        runSavedStrikeRuleButton = new JButton("Run Strike Rule on proxy history");
        runSavedStrikeRuleButton.setEnabled(!StrikeRulesUtils.getSavedStrikeRules().keySet().isEmpty());
        runSavedStrikeRuleButton.addActionListener(e -> {
            JSONObject strikeRulesJSON = StrikeRulesUtils.getSavedStrikeRules();
            JPopupMenu savedStrikeRulesPopupMenu;
            if(strikeRulesJSON.keySet().isEmpty()) {
                savedStrikeRulesPopupMenu = new JPopupMenu();
                savedStrikeRulesPopupMenu.add(new JMenuItem("No Strike Rules are saved."));
            } else {
                savedStrikeRulesPopupMenu = StrikeRuleMenus.buildStrikeRuleMenu(strikeRulesJSON);
            }

            savedStrikeRulesPopupMenu.show(runSavedStrikeRuleButton, 0, runSavedStrikeRuleButton.getHeight());
        });
        this.generateStrikeRuleButton = new JButton("Generate Strike Rule");
        this.generateStrikeRuleButton.setBackground(Color.decode("#d86633"));
        this.generateStrikeRuleButton.setForeground(Color.white);
        this.generateStrikeRuleButton.addActionListener(e -> {
            JPopupMenu strikeRulePopupMenu = new JPopupMenu();
            strikeRulePopupMenu.setEnabled(!requestHistory.isEmpty());
            strikeRulePopupMenu.add(buildRunRegexScanMenu());
            strikeRulePopupMenu.add(buildRunDiffingScanMenu());
            strikeRulePopupMenu.show(generateStrikeRuleButton, 0, generateStrikeRuleButton.getHeight());
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
            generateStrikeRuleButton.setEnabled(false);
            httpRequestEditor.setRequest(HttpRequest.httpRequest(""));
            httpResponseEditor.setResponse(HttpResponse.httpResponse());
            Utils.resetHistory(false);
        });
        buttonPanel.add(clearButton);
        generateStrikeRuleButton.setEnabled(false);
        buttonPanel.add(runSavedStrikeRuleButton);
        buttonPanel.add(generateStrikeRuleButton);
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
            generateStrikeRuleButton.setEnabled(true);
            repeatStrikePanel.setInstructions("You now have requests and responses in the queue. Click the \"Generate Strike Rule\" button at the bottom right to start.");
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
            repeatStrikePanel.setStatus("Idle", false);
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