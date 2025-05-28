package burp.repeat.strike.utils;

import org.json.JSONObject;

import static burp.repeat.strike.RepeatStrikeExtension.api;
import static burp.repeat.strike.RepeatStrikeExtension.repeatStrikeTab;
import static burp.repeat.strike.utils.Utils.alert;

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

    public static void saveCustomScanChecks(JSONObject scanChecksJSON) {
        api.persistence().extensionData().setString("scanChecks", scanChecksJSON.toString());
        repeatStrikeTab.scanChecksEditor.loadData();
    }

    public static void addCustomScanCheck(String name, JSONObject scanCheck, JSONObject scanChecksJSON) {
        scanChecksJSON.put(name, scanCheck);
        saveCustomScanChecks(scanChecksJSON);
        repeatStrikeTab.scanChecksEditor.loadData();
    }

    public static void deleteCustomScanCheck(String name, JSONObject scanChecksJSON) {
        scanChecksJSON.remove(name);
        saveCustomScanChecks(scanChecksJSON);
        repeatStrikeTab.scanChecksEditor.loadData();
    }

    public static void deleteAllScanChecks() {
        saveCustomScanChecks(new JSONObject());
        repeatStrikeTab.scanChecksEditor.loadData();
    }
}
