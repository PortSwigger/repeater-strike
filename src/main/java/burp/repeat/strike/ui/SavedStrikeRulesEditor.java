package burp.repeat.strike.ui;

import burp.repeat.strike.utils.StrikeRulesUtils;
import org.json.JSONException;
import org.json.JSONObject;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

import static burp.repeat.strike.utils.Utils.alert;
import static burp.repeat.strike.utils.Utils.confirm;

public class SavedStrikeRulesEditor extends JPanel {
    private JSONObject strikeRuleJSON;
    private final JComboBox<String> strikeRuleComboBox = new JComboBox<>();
    private final JTextArea codeEditor = new JTextArea(20, 100);
    public SavedStrikeRulesEditor() {
        super(new BorderLayout());
        SwingUtilities.invokeLater(this::buildInterface);
    }

    public void loadData() {
        strikeRuleJSON = StrikeRulesUtils.getSavedStrikeRules();
        List<String> options = new ArrayList<>();
        options.add("Please select");
        options.addAll(strikeRuleJSON.keySet());
        strikeRuleComboBox.setModel(new DefaultComboBoxModel<>(options.toArray(new String[0])));
        codeEditor.setText("");
    }

    public void buildInterface() {
        JPanel topPanel = new JPanel();
        JButton deleteAllStrikeRulesButton = new JButton("Delete All Strike Rules");
        deleteAllStrikeRulesButton.addActionListener(e -> {
            JSONObject strikeRuleJSON = StrikeRulesUtils.getSavedStrikeRules();
            if(strikeRuleJSON.isEmpty()) {
                return;
            }
            if (confirm(null, "Confirm delete Strike Rule", "Are you sure you want to delete all saved Strike Rules?")) {
                StrikeRulesUtils.deleteAllStrikeRules();
            }
        });
        topPanel.add(deleteAllStrikeRulesButton);
        JLabel strikeRulesLabel = new JLabel("Strike Rules");
        topPanel.add(strikeRulesLabel);
        topPanel.add(strikeRuleComboBox);
        JPanel editorPanel = new JPanel();
        editorPanel.setLayout(new BorderLayout());
        strikeRuleComboBox.addActionListener(e -> {
            if(strikeRuleComboBox.getSelectedIndex() == 0) {
                codeEditor.setText("");
                return;
            }
            String selectedItem = (String) strikeRuleComboBox.getSelectedItem();
            codeEditor.setText(strikeRuleJSON.getJSONObject(selectedItem).toString(4));
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
            if(strikeRuleComboBox.getSelectedIndex() == 0) {
                return;
            }
            if(confirm(null, "Confirm delete Strike Rule", "Are you sure you want to this Strike Rule?")) {
                String selectedItem = (String) strikeRuleComboBox.getSelectedItem();
                StrikeRulesUtils.deleteStrikeRule(selectedItem, strikeRuleJSON);
                codeEditor.setText("");
            }
        });
        JButton saveButton = new JButton("Save");
        saveButton.addActionListener(e -> {
            if(strikeRuleComboBox.getSelectedIndex() == 0) {
                return;
            }
            String selectedItem = (String) strikeRuleComboBox.getSelectedItem();
            int selectedIndex = strikeRuleComboBox.getSelectedIndex();
            try {
                strikeRuleJSON.put(selectedItem, new JSONObject(codeEditor.getText()));
                StrikeRulesUtils.saveStrikeRule(strikeRuleJSON);
                strikeRuleComboBox.setSelectedIndex(selectedIndex);
            } catch (JSONException ex) {
                alert("Invalid JSON saved failed:" + ex.getMessage());
            }
        });
        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.CENTER));
        row1.add(deleteButton);
        row1.add(saveButton);
        bottomPanel.add(row1);
        this.add(topPanel, BorderLayout.NORTH);
        this.add(editorPanel, BorderLayout.CENTER);
        this.add(bottomPanel, BorderLayout.SOUTH);
        loadData();
    }
}
