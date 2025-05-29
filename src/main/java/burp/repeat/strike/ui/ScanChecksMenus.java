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
import burp.repeat.strike.utils.Utils;
import org.json.JSONObject;

import javax.swing.*;
import java.util.HashSet;
import java.util.Set;

import static burp.repeat.strike.RepeatStrikeExtension.*;
import static burp.repeat.strike.ai.VulnerabilityAnalysis.compileScanCheck;
import static burp.repeat.strike.utils.Utils.alert;

public class ScanChecksMenus {

    public static JMenuItem buildAddToRepeatStrikeMenu(ContextMenuEvent event, RepeatStrikeTab repeatStrikeTab) {
        JMenuItem addToRepeatStrike = new JMenuItem("Send to Repeat Strike");
        addToRepeatStrike.addActionListener(e -> {
            if (event.messageEditorRequestResponse().isPresent()) {
                HttpRequest req = event.messageEditorRequestResponse().get().requestResponse().request();
                HttpResponse resp = event.messageEditorRequestResponse().get().requestResponse().response();
                if (req == null || resp == null) {
                    alert("Repeat Strike requires a request and response.");
                    return;
                }
                if(!req.isInScope()) {
                    alert("This request is not in scope");
                    return;
                }
                requestHistory.add(req);
                responseHistory.add(resp);
                repeatStrikeTab.addRequestResponse(event.messageEditorRequestResponse().get().requestResponse());
            }
        });
        return addToRepeatStrike;
    }

    public static JMenuItem buildRunDiffingScanMenu(){
        JMenuItem runRepeatStrikeDiffing = new JMenuItem("Using Diffing Non-AI");
        runRepeatStrikeDiffing.setEnabled(requestHistory.size() > 1);
        runRepeatStrikeDiffing.addActionListener(e -> {
            VulnerabilityAnalysis.generateScanCheck(requestHistory.toArray(new HttpRequest[0]), responseHistory.toArray(new HttpResponse[0]), VulnerabilityScanType.DiffingNonAi);
            Utils.resetHistory(false);
        });
        return runRepeatStrikeDiffing;
    }

    public static JMenuItem buildRunRegexScanMenu() {
        JMenuItem runRepeatStrikeRegex = new JMenuItem("Using AI Regex");
        runRepeatStrikeRegex.setEnabled(!requestHistory.isEmpty());
        runRepeatStrikeRegex.addActionListener(e -> {
            VulnerabilityAnalysis.generateScanCheck(requestHistory.toArray(new HttpRequest[0]), responseHistory.toArray(new HttpResponse[0]), VulnerabilityScanType.Regex);
            Utils.resetHistory(false);
        });
        return runRepeatStrikeRegex;
    }

    public static JMenuItem buildRunJavaScanMenu() {
        JMenuItem runRepeatStrikeJava = new JMenuItem("Using AI Java");
        runRepeatStrikeJava.setEnabled(!requestHistory.isEmpty());
        runRepeatStrikeJava.addActionListener(e -> {
            VulnerabilityAnalysis.generateScanCheck(requestHistory.toArray(new HttpRequest[0]), responseHistory.toArray(new HttpResponse[0]), VulnerabilityScanType.Java);
            Utils.resetHistory(false);
        });
        return runRepeatStrikeJava;
    }

    public static JPopupMenu buildScanCheckMenu(JSONObject scanChecksJSON) {
        JPopupMenu savedScanChecks = new JPopupMenu();
        if(!scanChecksJSON.isEmpty()) {
            scanChecksJSON.keySet().stream().sorted().forEach(key -> {
                JMenuItem runScanCheck = new JMenuItem(key);
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
                    } else if(scanCheck.getString("type").equals(VulnerabilityScanType.Java.name())) {
                        RepeatStrikeExtension.executorService.submit(() -> {
                            try {
                                Set<String> requestKeys = new HashSet<>();
                                String javaCode = scanCheck.getString("code");
                                Object compiledScanCheck = compileScanCheck(javaCode);
                                AnalyseProxyHistory.analyseWithObject(requestKeys, compiledScanCheck);
                            } catch (UnregisteredSettingException | InvalidTypeSettingException ex) {
                                throw new RuntimeException(ex);
                            } finally {
                                lastScanCheckRan = new JSONObject();
                            }
                        });
                    }
                });
                savedScanChecks.add(runScanCheck);
            });
        }
        return savedScanChecks;
    }
}
