package burp.repeat.strike.utils;

import burp.repeat.strike.RepeatStrikeExtension;
import burp.repeat.strike.ai.VulnerabilityScanType;
import burp.repeat.strike.proxy.AnalyseProxyHistory;
import burp.repeat.strike.settings.InvalidTypeSettingException;
import burp.repeat.strike.settings.UnregisteredSettingException;
import org.json.JSONObject;

import javax.swing.*;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.concurrent.Future;

import static burp.repeat.strike.RepeatStrikeExtension.*;
import static burp.repeat.strike.ai.VulnerabilityAnalysis.compileScanCheck;
import static burp.repeat.strike.utils.Utils.alert;
import static burp.repeat.strike.utils.Utils.prompt;

public class ScanCheckUtils {
    public static boolean validateScanCheckName(String name) {
        if(name == null || name.isEmpty()) {
            alert("The scan check name was empty");
            return false;
        }
        if(name.length() > 100) {
            alert("The scan check name was too long");
            return false;
        }
        String scanCheckNameRegex = "^\\w[\\s\\w\\-]*$";
        return name.matches(scanCheckNameRegex);
    }

    public static JSONObject getSavedCustomScanChecks() {
        String scanChecksString = api.persistence().extensionData().getString("scanChecks");
        JSONObject scanChecksJSON;
        if(scanChecksString == null) {
            scanChecksJSON = new JSONObject();
        } else {
            scanChecksJSON = new JSONObject(scanChecksString);
        }
        return scanChecksJSON;
    }

    public static boolean saveGeneratedScanCheck(JSONObject lastScanCheckRan){
        JSONObject scanChecksJSON = ScanCheckUtils.getSavedCustomScanChecks();
        if(lastScanCheckRan == null || lastScanCheckRan.isEmpty()) {
            alert("Unable to save generated scan check");
            return false;
        }
        String scanCheckName = prompt(null, "Save Last Scan", "Enter the name of your scan check:");
        if(!ScanCheckUtils.validateScanCheckName(scanCheckName)) {
            alert("Invalid scan check name.");
            return false;
        }
        ScanCheckUtils.addCustomScanCheck(scanCheckName, lastScanCheckRan, scanChecksJSON);
        return true;
    }

    public static void saveCustomScanChecks(JSONObject scanChecksJSON) {
        api.persistence().extensionData().setString("scanChecks", scanChecksJSON.toString());
        repeatStrikeTab.scanChecksEditor.loadData();
    }

    public static void addCustomScanCheck(String name, JSONObject scanCheck, JSONObject scanChecksJSON) {
        scanChecksJSON.put(name, scanCheck);
        saveCustomScanChecks(scanChecksJSON);
        repeatStrikeTab.scanChecksEditor.loadData();
        repeatStrikeTab.runSavedScanChecksButton.setEnabled(true);
    }

    public static void deleteCustomScanCheck(String name, JSONObject scanChecksJSON) {
        scanChecksJSON.remove(name);
        saveCustomScanChecks(scanChecksJSON);
        if(scanChecksJSON.keySet().isEmpty()) {
            repeatStrikeTab.runSavedScanChecksButton.setEnabled(false);
        }
        repeatStrikeTab.scanChecksEditor.loadData();
    }

    public static void deleteAllScanChecks() {
        saveCustomScanChecks(new JSONObject());
        repeatStrikeTab.scanChecksEditor.loadData();
        repeatStrikeTab.runSavedScanChecksButton.setEnabled(false);
    }

    public static void scanProxyHistory(JSONObject scanCheck) {
        if(scanCheck.getString("type").equals(VulnerabilityScanType.DiffingNonAi.name())) {
            Future<?> future = RepeatStrikeExtension.executorService.submit(() -> {
                try {
                    AnalyseProxyHistory.analyseWithDiffing(scanCheck.getString("value"));
                } catch (UnregisteredSettingException | InvalidTypeSettingException ex) {
                    throw new RuntimeException(ex);
                }
            });
            try {
                future.get();
            } catch (Throwable throwable) {
                StringWriter writer = new StringWriter();
                throwable.printStackTrace(new PrintWriter(writer));
                api.logging().logToError(writer.toString());
            }
        } else if(scanCheck.getString("type").equals(VulnerabilityScanType.Regex.name())) {
            Future<?> future = RepeatStrikeExtension.executorService.submit(() -> {
                try {
                    AnalyseProxyHistory.analyseWithRegex(scanCheck.getJSONObject("analysis"), scanCheck.getJSONObject("param"));
                } catch (UnregisteredSettingException | InvalidTypeSettingException ex) {
                    throw new RuntimeException(ex);
                }
            });
            try {
                future.get();
            } catch (Throwable throwable) {
                StringWriter writer = new StringWriter();
                throwable.printStackTrace(new PrintWriter(writer));
                api.logging().logToError(writer.toString());
            }
        } else if(scanCheck.getString("type").equals(VulnerabilityScanType.Java.name())) {
            Future<?> future = RepeatStrikeExtension.executorService.submit(() -> {
                try {
                    String javaCode = scanCheck.getString("code");
                    Object compiledScanCheck = compileScanCheck(javaCode);
                    AnalyseProxyHistory.analyseWithObject(compiledScanCheck);
                } catch (UnregisteredSettingException | InvalidTypeSettingException ex) {
                    throw new RuntimeException(ex);
                }
            });
            try {
                future.get();
            } catch (Throwable throwable) {
                StringWriter writer = new StringWriter();
                throwable.printStackTrace(new PrintWriter(writer));
                api.logging().logToError(writer.toString());
            }
        }
    }
}
