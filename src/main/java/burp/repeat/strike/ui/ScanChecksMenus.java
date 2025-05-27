package burp.repeat.strike.ui;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.repeat.strike.RepeatStrikeExtension;
import burp.repeat.strike.ai.VulnerabilityAnalysis;
import burp.repeat.strike.ai.VulnerabilityScanType;
import burp.repeat.strike.proxy.AnalyseProxyHistory;
import burp.repeat.strike.settings.InvalidTypeSettingException;
import burp.repeat.strike.settings.UnregisteredSettingException;
import burp.repeat.strike.utils.ScanCheckUtils;
import burp.repeat.strike.utils.Utils;
import org.json.JSONObject;

import javax.swing.*;
import java.util.HashSet;
import java.util.Set;

import static burp.repeat.strike.RepeatStrikeExtension.*;
import static burp.repeat.strike.utils.Utils.*;

public class ScanChecksMenus {

    public static JMenuItem buildAddToRepeatStrikeMenu(ContextMenuEvent event) {
        JMenuItem addToRepeatStrike = new JMenuItem("Send to Repeat Strike");
        addToRepeatStrike.addActionListener(e -> {
            if (event.messageEditorRequestResponse().isPresent()) {
                HttpRequest req = event.messageEditorRequestResponse().get().requestResponse().request();
                HttpResponse resp = event.messageEditorRequestResponse().get().requestResponse().response();
                if (req == null || resp == null) {
                    return;
                }
                requestHistory.add(req);
                responseHistory.add(resp);
            }
        });
        return addToRepeatStrike;
    }

    public static JMenuItem buildDeleteAllScanChecksMenu(JSONObject scanChecksJSON) {
        JMenuItem deleteScanChecks = new JMenuItem("Delete all saved scan checks");
        deleteScanChecks.setEnabled(scanChecksJSON != null && !scanChecksJSON.isEmpty());
        deleteScanChecks.addActionListener(e -> {
            if (confirm(null, "Confirm delete scan checks", "Are you sure you want to delete all saved scan checks?")) {
                ScanCheckUtils.deleteAllScanChecks();
            }
        });
        return deleteScanChecks;
    }

    public static JMenuItem buildResetMenu() {
        JMenuItem resetMenu = new JMenuItem("Empty requests/responses");
        resetMenu.setEnabled(!requestHistory.isEmpty());
        resetMenu.addActionListener(e -> Utils.resetHistory(false));
        return resetMenu;
    }

    public static JMenuItem buildRunDiffingScanMenu(){
        JMenuItem runRepeatStrikeDiffing = new JMenuItem("Using Diffing Non-AI (" + requestHistory.size() + ")");
        runRepeatStrikeDiffing.setEnabled(requestHistory.size() > 1);
        runRepeatStrikeDiffing.addActionListener(e -> {
            VulnerabilityAnalysis.check(requestHistory.toArray(new HttpRequest[0]), responseHistory.toArray(new HttpResponse[0]), VulnerabilityScanType.DiffingNonAi);
            Utils.resetHistory(false);
        });
        return runRepeatStrikeDiffing;
    }

    public static JMenuItem buildRunRegexScanMenu() {
        JMenuItem runRepeatStrikeRegex = new JMenuItem("Using AI Regex (" + requestHistory.size() + ")");
        runRepeatStrikeRegex.setEnabled(!requestHistory.isEmpty());
        runRepeatStrikeRegex.addActionListener(e -> {
            VulnerabilityAnalysis.check(requestHistory.toArray(new HttpRequest[0]), responseHistory.toArray(new HttpResponse[0]), VulnerabilityScanType.Regex);
            Utils.resetHistory(false);
        });
        return runRepeatStrikeRegex;
    }

    public static JMenuItem buildRunJavaScanMenu() {
        JMenuItem runRepeatStrikeJava = new JMenuItem("Using AI Java (" + requestHistory.size() + ")");
        runRepeatStrikeJava.setEnabled(!requestHistory.isEmpty());
        runRepeatStrikeJava.addActionListener(e -> {
            VulnerabilityAnalysis.check(requestHistory.toArray(new HttpRequest[0]), responseHistory.toArray(new HttpResponse[0]), VulnerabilityScanType.Java);
            Utils.resetHistory(false);
        });
        return runRepeatStrikeJava;
    }

    public static JMenuItem buildSaveLastScanCheckMenu(JSONObject scanChecksJSON) {
        JMenuItem saveLastScanCheck = new JMenuItem("Save last scan check");
        saveLastScanCheck.setEnabled(lastScanCheckRan != null && !lastScanCheckRan.isEmpty());
        saveLastScanCheck.addActionListener(e -> {
            if(lastScanCheckRan != null) {
                if(lastScanCheckRan.getString("type").equals(VulnerabilityScanType.Java.name())) {
                    alert("Repeat Strike can't save Java scan checks yet.");
                    return;
                }
                String scanCheckName = prompt(null, "Save Last Scan", "Enter the name of your scan check:");
                if(!ScanCheckUtils.validateScanCheckName(scanCheckName)) {
                    alert("Invalid scan check name.");
                    return;
                }
                ScanCheckUtils.addCustomScanCheck(scanCheckName, lastScanCheckRan, scanChecksJSON);
                lastScanCheckRan = null;
            }
        });
        return saveLastScanCheck;
    }

    public static JMenu buildScanCheckMenu(JSONObject scanChecksJSON) {
        JMenu savedScanChecks = new JMenu("Saved scan checks");
        savedScanChecks.setEnabled(!scanChecksJSON.isEmpty());
        if(!scanChecksJSON.isEmpty()) {
            scanChecksJSON.keySet().stream().sorted().forEach(key -> {
                JMenu scanCheckMenu = new JMenu(key);
                JMenuItem runScanCheck = new JMenuItem("Scan proxy history");
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
                    if(confirm(null, "Confirm delete scan check", "Are you sure you want to this scan check?")) {
                        ScanCheckUtils.deleteCustomScanCheck(key, scanChecksJSON);
                    }
                });
                scanCheckMenu.add(deleteScanCheck);
                savedScanChecks.add(scanCheckMenu);
            });
        }
        return savedScanChecks;
    }
}
