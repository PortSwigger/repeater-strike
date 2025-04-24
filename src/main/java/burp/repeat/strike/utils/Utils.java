package burp.repeat.strike.utils;


import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.repeat.strike.RepeatStrikeExtension;
import burp.repeat.strike.settings.InvalidTypeSettingException;
import burp.repeat.strike.settings.Settings;
import burp.repeat.strike.settings.UnregisteredSettingException;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;

import static burp.repeat.strike.RepeatStrikeExtension.*;

public class Utils {

    public static boolean isVulnerable(HttpResponse response, String regex) {
        try {
            return Pattern.compile(regex).matcher(response.toString()).find();
        } catch (PatternSyntaxException e) {
            return false;
        }
    }
    public static boolean isUrlEncoded(String value) {
        return Pattern.compile("%[a-fA-F0-9]{2}").matcher(value).find();
    }
    public static HttpRequest modifyRequest(HttpRequest req, String type, String name, String value) {
        type = type.toUpperCase();
        return switch (type) {
            case "HEADER" -> req.withRemovedHeader(name).withAddedHeader(name, value);
            case "PATH" -> req.withPath(value);
            case "URL", "BODY", "COOKIE", "JSON" -> {
                if ((type.equals("BODY") || type.equals("URL")) && !isUrlEncoded(value)) {
                    value = api.utilities().urlUtils().encode(value);
                }
                yield req.withUpdatedParameters(HttpParameter.parameter(name, value, HttpParameterType.valueOf(type)));
            }
            default -> req;
        };
    }

    public static void registerGeneralSettings(Settings settings) {
        settings.registerBooleanSetting("debugOutput", false, "Print debug output", "General", null);
        settings.registerBooleanSetting("debugAi", false, "Debug AI requests/responses", "AI", null);
        settings.registerBooleanSetting("autoInvoke", false, "Auto invoke after repeater requests", "Repeater settings", null);
        settings.registerIntegerSetting("maxProxyHistory", 100, "Max proxy history to scan", "Limits", 1, 500);
        settings.registerIntegerSetting("maxImageResponseLimit", 1000, "Maximum image response limit (1-128000)", "Limits", 1, 128000);
        settings.registerIntegerSetting("maxRequestLimit", 100000, "Maximum request limit (1-128000)", "Limits", 1, 128000);
        settings.registerIntegerSetting("maxResponseLimit", 100000, "Maximum response limit (1-128000)", "Limits", 1, 128000);
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
        return currentHost + paramNames;
    }

    public static void resetHistory(String key, boolean shouldDebug) {
        requestHistoryPos.put(key,1);
        requestHistory.put(key, new ArrayList<>());
        responseHistory.put(key, new ArrayList<>());
        if(shouldDebug) {
            api.logging().logToOutput("Request history reset");
        }
    }
    public static String truncateRequest(HttpRequest request) {
        int maxRequestLimit;
        try {
            maxRequestLimit = RepeatStrikeExtension.generalSettings.getInteger("maxRequestLimit");
        } catch (UnregisteredSettingException | InvalidTypeSettingException e) {
            api.logging().logToError("Error loading settings:" + e);
            throw new RuntimeException(e);
        }
        String output = request.toString();
        if(output.length() > maxRequestLimit) {
            output = output.substring(0, maxRequestLimit);
        }
        return output;
    }
    public static String truncateResponse(HttpResponse response) {
        int maxImageResponseLimit;
        int maxResponseLimit;
        try {
            maxImageResponseLimit = RepeatStrikeExtension.generalSettings.getInteger("maxImageResponseLimit");
            maxResponseLimit = RepeatStrikeExtension.generalSettings.getInteger("maxResponseLimit");
        } catch (UnregisteredSettingException | InvalidTypeSettingException e) {
            api.logging().logToError("Error loading settings:" + e);
            throw new RuntimeException(e);
        }
        String output = response.toString();
        if(response.mimeType().toString().toLowerCase().startsWith("image") && output.length() > maxImageResponseLimit) {
            output = output.substring(0, maxImageResponseLimit);
        }
        if(output.length() > maxResponseLimit) {
            output = output.substring(0, maxResponseLimit);
        }
        return output;
    }
}
