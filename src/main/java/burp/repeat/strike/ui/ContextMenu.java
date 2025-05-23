package burp.repeat.strike.ui;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.InvocationType;
import burp.repeat.strike.RepeatStrikeExtension;
import burp.repeat.strike.ai.VulnerabilityAnalysis;
import burp.repeat.strike.ai.VulnerabilityScanType;
import burp.repeat.strike.proxy.AnalyseProxyHistory;
import burp.repeat.strike.settings.InvalidTypeSettingException;
import burp.repeat.strike.settings.Settings;
import burp.repeat.strike.settings.UnregisteredSettingException;
import burp.repeat.strike.utils.Utils;
import org.json.JSONObject;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

import static burp.repeat.strike.RepeatStrikeExtension.*;


public class ContextMenu implements ContextMenuItemsProvider {
    public java.util.List<Component> provideMenuItems(ContextMenuEvent event)
    {
        java.util.List<Component> menuItemList = new ArrayList<>();
        if(event.messageEditorRequestResponse().isPresent() && event.invocationType() == InvocationType.MESSAGE_EDITOR_REQUEST && event.isFromTool(ToolType.REPEATER)) {
            JMenuItem addToRepeatStrike = new JMenuItem("Add to Repeat Strike");
            addToRepeatStrike.addActionListener(e -> {
                if(event.messageEditorRequestResponse().isPresent()) {
                    HttpRequest req = event.messageEditorRequestResponse().get().requestResponse().request();
                    HttpResponse resp = event.messageEditorRequestResponse().get().requestResponse().response();
                    if (req == null || resp == null) {
                        return;
                    }
                    requestHistory.add(req);
                    responseHistory.add(resp);
                }
            });
            menuItemList.add(addToRepeatStrike);
            JMenuItem runRepeatStrikeJava = new JMenuItem("Scan using AI Java ("+requestHistory.size()+")");
            runRepeatStrikeJava.setEnabled(!requestHistory.isEmpty() && requestHistory.size() < 3);
            runRepeatStrikeJava.addActionListener(e -> {
                VulnerabilityAnalysis.check(requestHistory.toArray(new HttpRequest[0]), responseHistory.toArray(new HttpResponse[0]), VulnerabilityScanType.Java);
                Utils.resetHistory(false);
            });
            menuItemList.add(runRepeatStrikeJava);
            JMenuItem runRepeatStrikeRegex = new JMenuItem("Scan using AI Regex ("+requestHistory.size()+")");
            runRepeatStrikeRegex.setEnabled(!requestHistory.isEmpty() && requestHistory.size() < 3);
            runRepeatStrikeRegex.addActionListener(e -> {
                VulnerabilityAnalysis.check(requestHistory.toArray(new HttpRequest[0]), responseHistory.toArray(new HttpResponse[0]), VulnerabilityScanType.Regex);
                Utils.resetHistory(false);
            });
            menuItemList.add(runRepeatStrikeRegex);
            JMenuItem runRepeatStrikeDiffing = new JMenuItem("Scan using Diffing Non-AI ("+requestHistory.size()+")");
            runRepeatStrikeDiffing.setEnabled(requestHistory.size() > 1);
            runRepeatStrikeDiffing.addActionListener(e -> {
                VulnerabilityAnalysis.check(requestHistory.toArray(new HttpRequest[0]), responseHistory.toArray(new HttpResponse[0]), VulnerabilityScanType.DiffingNonAi);
                Utils.resetHistory(false);
            });
            menuItemList.add(runRepeatStrikeDiffing);
        }
        String scanChecksString = api.persistence().extensionData().getString("scanChecks");
        JSONObject scanChecksJSON;
        if(scanChecksString == null) {
            scanChecksJSON = new JSONObject();
        } else {
            scanChecksJSON = new JSONObject(scanChecksString);
        }
        JMenu savedScanChecks = new JMenu("Saved scan checks");
        savedScanChecks.setEnabled(!scanChecksJSON.isEmpty());
        if(!scanChecksJSON.isEmpty()) {
            scanChecksJSON.keySet().stream().sorted().forEach(key -> {
                JMenu scanCheckMenu = new JMenu(key);
                JMenuItem runScanCheck = new JMenuItem("Run");
                runScanCheck.addActionListener(e -> {
                   JSONObject scanCheck = scanChecksJSON.getJSONObject(key);
                   if(scanCheck.getString("type").equals(VulnerabilityScanType.DiffingNonAi.name())) {
                       RepeatStrikeExtension.executorService.submit(() -> {
                           try {
                               Set<String> requestKeys = new HashSet<>();
                               AnalyseProxyHistory.analyseWithDiffing(requestKeys, (short) scanCheck.getInt("statusCode"), scanCheck.getString("value"));
                           } catch (UnregisteredSettingException | InvalidTypeSettingException ex) {
                               throw new RuntimeException(ex);
                           } finally {
                               lastScanCheckRan = new JSONObject();
                           }
                       });
                   } else if(scanCheck.getString("type").equals(VulnerabilityScanType.Regex.name())) {
                       RepeatStrikeExtension.executorService.submit(() -> {
                           try {
                               Set<String> requestKeys = new HashSet<>();
                               AnalyseProxyHistory.analyseWithRegex(requestKeys, scanCheck.getJSONObject("analysis"), scanCheck.getJSONObject("param"));
                           } catch (UnregisteredSettingException | InvalidTypeSettingException ex) {
                               throw new RuntimeException(ex);
                           } finally {
                               lastScanCheckRan = new JSONObject();
                           }
                       });
                   }
                });
                scanCheckMenu.add(runScanCheck);
                JMenuItem deleteScanCheck = new JMenuItem("Delete");
                deleteScanCheck.addActionListener(e -> {
                    int confirm = JOptionPane.showConfirmDialog(null, "Are you sure you want to this scan check?", "Confirm", JOptionPane.YES_NO_OPTION);
                    if(confirm == 0) {
                        scanChecksJSON.remove(key);
                        api.persistence().extensionData().setString("scanChecks", scanChecksJSON.toString());
                    }
                });
                scanCheckMenu.add(deleteScanCheck);
               savedScanChecks.add(scanCheckMenu);
            });
        }
        menuItemList.add(savedScanChecks);
        JMenuItem saveLastScanCheck = new JMenuItem("Save last scan check");
        saveLastScanCheck.setEnabled(lastScanCheckRan != null && !lastScanCheckRan.isEmpty());
        saveLastScanCheck.addActionListener(e -> {
            if(lastScanCheckRan != null) {
                if(lastScanCheckRan.getString("type").equals(VulnerabilityScanType.Java.name())) {
                    JOptionPane.showMessageDialog(null, "Repeat Strike can't save Java scan checks yet.");
                    return;
                }
                String scanCheckName = JOptionPane.showInputDialog(null, "Enter the name of your scan check:", "Save Last Scan", JOptionPane.QUESTION_MESSAGE);
                if(!Utils.validateScanCheckName(scanCheckName)) {
                    JOptionPane.showMessageDialog(null, "Invalid scan check name.");
                    return;
                }
                scanChecksJSON.put(scanCheckName, lastScanCheckRan);
                api.persistence().extensionData().setString("scanChecks", scanChecksJSON.toString());
                lastScanCheckRan = null;
            }
        });
        menuItemList.add(saveLastScanCheck);

        JMenuItem resetMenu = new JMenuItem("Empty requests/responses");
        resetMenu.setEnabled(!requestHistory.isEmpty());
        resetMenu.addActionListener(e -> Utils.resetHistory(false));
        menuItemList.add(resetMenu);

        JMenuItem deleteScanChecks = new JMenuItem("Delete all saved scan checks");
        deleteScanChecks.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(null, "Are you sure you want to delete all saved scan checks?", "Confirm", JOptionPane.YES_NO_OPTION);
            if(confirm == 0) {
                api.persistence().extensionData().setString("scanChecks", new JSONObject().toString());
            }
        });
        menuItemList.add(deleteScanChecks);

        JMenuItem settings = new JMenuItem("Settings");
        settings.addActionListener(e -> Settings.showSettingsWindow());
        menuItemList.add(settings);

        return menuItemList;
    }
}
