package burp.repeat.strike.utils;

import org.json.JSONObject;

import static burp.repeat.strike.RepeatStrikeExtension.api;

public class ScanCheckUtils {
    public static boolean validateScanCheckName(String name) {
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
    }

    public static void addCustomScanCheck(String name, JSONObject scanCheck, JSONObject scanChecksJSON) {
        scanChecksJSON.put(name, scanCheck);
        saveCustomScanChecks(scanChecksJSON);
    }

    public static void deleteCustomScanCheck(String name, JSONObject scanChecksJSON) {
        scanChecksJSON.remove(name);
        saveCustomScanChecks(scanChecksJSON);
    }

    public static void deleteAllScanChecks() {
        saveCustomScanChecks(new JSONObject());
    }
}
