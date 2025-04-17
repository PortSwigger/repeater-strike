package burp.repeat.strike.utils;


import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.repeat.strike.RepeatStrikeExtension;
import burp.repeat.strike.settings.Settings;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.stream.Collectors;

import static burp.repeat.strike.RepeatStrikeExtension.*;

public class Utils {

    public static void registerGeneralSettings(Settings settings) {
        settings.registerBooleanSetting("debugOutput", false, "Print debug output", "General", null);
        settings.registerBooleanSetting("debugAi", false, "Debug AI requests/responses", "AI", null);
    }

    public static void openUrl(String url) {
        if(url.startsWith("https://")) {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                try {
                    Desktop.getDesktop().browse(new URI(url));
                } catch (IOException | URISyntaxException ignored) {
                }
            }
        }
    }

    public static JFrame getSettingsWindowInstance() {
        if(SettingsFrame != null) {
            return SettingsFrame;
        }
        SettingsFrame = new JFrame();
        SettingsFrame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                SettingsFrame.setVisible(false);
                SettingsFrame.getContentPane().removeAll();
                SettingsFrame.getContentPane().setLayout(new BorderLayout());
            }
        });
        return SettingsFrame;
    }

    public static JMenu generateMenuBar() {
        JMenu menuBar = new JMenu(RepeatStrikeExtension.extensionName);
        JMenuItem settingsMenu = new JMenuItem("Settings");
        settingsMenu.addActionListener(e -> Settings.showSettingsWindow());
        menuBar.add(settingsMenu);
        JMenuItem reportFeedbackMenu = new JMenuItem("Report feedback");
        reportFeedbackMenu.addActionListener(e -> {
            Utils.openUrl("https://github.com/hackvertor/auto-notes/issues/new");
        });
        menuBar.add(reportFeedbackMenu);
        return menuBar;
    }

    public static ImageIcon createImageIcon(String path, String description) {
        java.net.URL imgURL = RepeatStrikeExtension.class.getResource(path);
        if (imgURL != null) {
            return new ImageIcon(imgURL, description);
        } else {
            api.logging().logToError("Couldn't find file: " + path);
            return null;
        }
    }

    public static boolean checkIfCanSetNotes(Annotations annotations) {
        try {
            String notes = annotations.notes();
            annotations.setNotes(notes);
            return true;
        } catch(UnsupportedOperationException ignored) {
            return false;
        }
    }

    public static String generateRequestKey(HttpRequest req) {
        String currentHost = req.httpService().host();
        String paramNames = req.parameters().stream().map(ParsedHttpParameter::name).collect(Collectors.joining(","));
        String requestKey = currentHost + paramNames;
        if(!requestHistoryPos.containsKey(requestKey)) {
            requestHistoryPos.put(requestKey, 1);
            requestHistory.put(requestKey, new ArrayList<>());
            responseHistory.put(requestKey, new ArrayList<>());
        }
        return requestKey;
    }

    public static void resetHistory(String key, boolean shouldDebug) {
        requestHistoryPos.put(key,1);
        requestHistory.put(key, new ArrayList<>());
        responseHistory.put(key, new ArrayList<>());
        if(shouldDebug) {
            api.logging().logToOutput("Request history reset");
        }
    }
}
