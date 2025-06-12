package burp.repeat.strike.ui;

import burp.repeat.strike.utils.ScanCheckUtils;
import org.json.JSONException;
import org.json.JSONObject;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

import static burp.repeat.strike.utils.Utils.alert;
import static burp.repeat.strike.utils.Utils.confirm;

public class SavedScanChecksEditor extends JPanel {
    private JSONObject scanChecksJSON;
    private final JComboBox<String> scanChecksComboBox = new JComboBox<>();
    private final JTextArea codeEditor = new JTextArea(20, 100);
    public SavedScanChecksEditor() {
        super(new BorderLayout());
        SwingUtilities.invokeLater(this::buildInterface);
    }

    public void loadData() {
        scanChecksJSON = ScanCheckUtils.getSavedCustomScanChecks();
        List<String> options = new ArrayList<>();
        options.add("Please select");
        options.addAll(scanChecksJSON.keySet());
        scanChecksComboBox.setModel(new DefaultComboBoxModel<>(options.toArray(new String[0])));
        codeEditor.setText("");
    }

    public void buildInterface() {
        JPanel topPanel = new JPanel();
        JButton deleteAllScanChecksButton = new JButton("Delete All Scan Checks");
        deleteAllScanChecksButton.addActionListener(e -> {
            JSONObject scanChecksJSON = ScanCheckUtils.getSavedCustomScanChecks();
            if(scanChecksJSON.isEmpty()) {
                return;
            }
            if (confirm(null, "Confirm delete scan checks", "Are you sure you want to delete all saved scan checks?")) {
                ScanCheckUtils.deleteAllScanChecks();
            }
        });
        topPanel.add(deleteAllScanChecksButton);
        JLabel scanCheckLabel = new JLabel("Scan Checks");
        topPanel.add(scanCheckLabel);
        topPanel.add(scanChecksComboBox);
        JPanel editorPanel = new JPanel();
        editorPanel.setLayout(new BorderLayout());
        scanChecksComboBox.addActionListener(e -> {
            if(scanChecksComboBox.getSelectedIndex() == 0) {
                codeEditor.setText("");
                return;
            }
            String selectedItem = (String) scanChecksComboBox.getSelectedItem();
            codeEditor.setText(scanChecksJSON.getJSONObject(selectedItem).toString(4));
        });
        codeEditor.setLineWrap(true);
        codeEditor.setWrapStyleWord(true);
        JScrollPane scrollPane = new JScrollPane(codeEditor);
        editorPanel.add(scrollPane, BorderLayout.CENTER);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        JPanel bottomPanel = new JPanel();
        bottomPanel.setLayout(new BoxLayout(bottomPanel, BoxLayout.Y_AXIS));
        JButton deleteButton = new JButton("Delete");
        deleteButton.addActionListener(e -> {
            if(scanChecksComboBox.getSelectedIndex() == 0) {
                return;
            }
            if(confirm(null, "Confirm delete scan check", "Are you sure you want to this scan check?")) {
                String selectedItem = (String) scanChecksComboBox.getSelectedItem();
                ScanCheckUtils.deleteCustomScanCheck(selectedItem, scanChecksJSON);
                codeEditor.setText("");
            }
        });
        JButton saveButton = new JButton("Save");
        saveButton.addActionListener(e -> {
            if(scanChecksComboBox.getSelectedIndex() == 0) {
                return;
            }
            String selectedItem = (String) scanChecksComboBox.getSelectedItem();
            int selectedIndex = scanChecksComboBox.getSelectedIndex();
            try {
                scanChecksJSON.put(selectedItem, new JSONObject(codeEditor.getText()));
                ScanCheckUtils.saveCustomScanChecks(scanChecksJSON);
                scanChecksComboBox.setSelectedIndex(selectedIndex);
            } catch (JSONException ex) {
                alert("Invalid JSON saved failed:" + ex.getMessage());
            }
        });
        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.CENTER));
        row1.add(deleteButton);
        row1.add(saveButton);
        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.CENTER));
        bottomPanel.add(row1);
        bottomPanel.add(row2);
        this.add(topPanel, BorderLayout.NORTH);
        this.add(editorPanel, BorderLayout.CENTER);
        this.add(bottomPanel, BorderLayout.SOUTH);
        loadData();
    }
}
