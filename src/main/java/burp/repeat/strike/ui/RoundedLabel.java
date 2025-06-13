package burp.repeat.strike.ui;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;


public class RoundedLabel extends JLabel {
    private Color backgroundColor;
    private int arc;

    public RoundedLabel(String text, Color foregroundColor, Color backgroundColor, int arc) {
        super(text);
        this.backgroundColor = backgroundColor;
        this.setForeground(foregroundColor);
        this.arc = arc;
        if(text.isEmpty()) {
            this.setVisible(false);
        }
        setOpaque(false);
        setBorder(new EmptyBorder(5, 10, 5, 10));
    }

    public void setArc(int arc) {
        this.arc = arc;
        repaint();
    }

    @Override
    public void setBackground(Color bg) {
        this.backgroundColor = bg;
        repaint();
    }

    @Override
    public Color getBackground() {
        return backgroundColor;
    }

    @Override
    public void setForeground(Color fg) {
        super.setForeground(fg);
        repaint();
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setColor(backgroundColor);
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.fillRoundRect(0, 0, getWidth(), getHeight(), arc, arc);
        g2.dispose();
        super.paintComponent(g);
    }
}

