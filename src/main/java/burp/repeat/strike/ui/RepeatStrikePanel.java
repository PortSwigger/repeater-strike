package burp.repeat.strike.ui;

import javax.swing.*;
import java.awt.*;

public class RepeatStrikePanel extends javax.swing.JPanel {
    private final String defaultInstructions = "Click on a request in Repeater, then right-click and select Extensions → Repeat Strike → Send to Repeat Strike to begin.";
    private final JLabel repeatStrikeDescription = new JLabel(defaultInstructions);
    private final RoundedLabel statusLabel = new RoundedLabel("Idle", Color.decode("#00533d"), Color.decode("#00d390"), 12);
    private final RoundedLabel repeatStrikeWordlistWarning = new RoundedLabel("", Color.decode("#793205"), Color.decode("#fcb700"), 12);

    public RepeatStrikePanel(RepeatStrikeTab repeatStrikeTab) {
        super(new BorderLayout());
        SwingUtilities.invokeLater(() -> {
            JPanel topPanel = new JPanel();
            topPanel.setLayout(new BoxLayout(topPanel, BoxLayout.Y_AXIS));
            JLabel repeatStrikeTitle = new JLabel("Repeat Strike");
            repeatStrikeTitle.setFont(new Font(repeatStrikeTitle.getFont().getName(), Font.BOLD, repeatStrikeTitle.getFont().getSize()+3));
            JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT));
            row1.add(repeatStrikeTitle);
            JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT));
            row2.add(repeatStrikeDescription);
            JPanel row3 = new JPanel(new FlowLayout(FlowLayout.LEFT));
            row3.add(repeatStrikeWordlistWarning);
            JPanel row4 = new JPanel(new FlowLayout(FlowLayout.LEFT));
            row4.add(new JLabel("Status:"));
            row4.add(statusLabel);
            row2.add(repeatStrikeDescription);
            topPanel.add(row1);
            topPanel.add(row2);
            topPanel.add(row3);
            topPanel.add(row4);
            this.add(topPanel, BorderLayout.NORTH);
            this.add(repeatStrikeTab, BorderLayout.CENTER);
        });
    }

    public void setWordListWarning(String warning) {
        repeatStrikeWordlistWarning.setText(warning);
        if(warning.isEmpty()) {
            repeatStrikeWordlistWarning.setVisible(false);
        } else {
            repeatStrikeWordlistWarning.setVisible(true);
        }
    }

    public void setStatus(String status, boolean isError) {
        statusLabel.setText(status);
        if(isError) {
            statusLabel.setForeground(Color.decode("#4d0218"));
            statusLabel.setBackground(Color.decode("#ff637d"));
        } else {
            statusLabel.setForeground(Color.decode("#00533d"));
            statusLabel.setBackground(Color.decode("#00d390"));
        }
    }

    public void resetInstructions() {
        this.setInstructions(defaultInstructions);
    }

    public void setInstructions(String instructions) {
        repeatStrikeDescription.setText(instructions);
    }
}
