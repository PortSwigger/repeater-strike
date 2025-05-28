package burp.repeat.strike.ui;

import javax.swing.*;
import java.awt.*;

public class RepeatStrikePanel extends javax.swing.JPanel {
    private final String defaultInstructions = "Go to Repeater and right click on a request Extensions->Repeat Strike->Send to Repeat Strike to begin";
    private final JLabel repeatStrikeDescription = new JLabel(defaultInstructions);
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
            topPanel.add(row1);
            topPanel.add(row2);
            this.add(topPanel, BorderLayout.NORTH);
            this.add(repeatStrikeTab, BorderLayout.CENTER);
        });
    }

    public void resetInstructions() {
        this.setInstructions(defaultInstructions);
    }

    public void setInstructions(String instructions) {
        repeatStrikeDescription.setText(instructions);
    }
}
