package burp.repeat.strike.utils;

import burp.repeat.strike.RepeatStrikeExtension;
import burp.repeat.strike.ai.VulnerabilityScanType;
import burp.repeat.strike.proxy.AnalyseProxyHistory;
import org.json.JSONObject;

import static burp.repeat.strike.RepeatStrikeExtension.*;
import static burp.repeat.strike.utils.Utils.alert;
import static burp.repeat.strike.utils.Utils.prompt;

public class StrikeRulesUtils {
    public static boolean validateStrikeRuleName(String name) {
        if(name == null || name.isEmpty()) {
            alert("The Strike Rule name was empty");
            return false;
        }
        if(name.length() > 100) {
            alert("The Strike Rule name was too long");
            return false;
        }
        String strikeRuleNameRegex = "^\\w[\\s\\w\\-]*$";
        if(!name.matches(strikeRuleNameRegex)) {
            alert("Invalid Strike Rule name.");
            return false;
        }
        return true;
    }

    public static JSONObject getSavedStrikeRules() {
        String strikeRulesString = api.persistence().extensionData().getString("strikeRules");
        JSONObject strikeRulesJSON;
        if(strikeRulesString == null) {
            strikeRulesJSON = new JSONObject();
        } else {
            strikeRulesJSON = new JSONObject(strikeRulesString);
        }
        return strikeRulesJSON;
    }

    public static boolean saveGeneratedStrikeRule(JSONObject lastStrikeRuleRan){
        JSONObject strikeRulesJSON = StrikeRulesUtils.getSavedStrikeRules();
        if(lastStrikeRuleRan == null || lastStrikeRuleRan.isEmpty()) {
            alert("Unable to save generated Strike Rule");
            return false;
        }
        String strikeRuleName = prompt(null, "Save Last Strike Rule", "Enter the name of your Strike Rule:");
        if(!StrikeRulesUtils.validateStrikeRuleName(strikeRuleName)) {
            return false;
        }
        StrikeRulesUtils.addStrikeRule(strikeRuleName, lastStrikeRuleRan, strikeRulesJSON);
        return true;
    }

    public static void saveStrikeRule(JSONObject strikeRulesJSON) {
        api.persistence().extensionData().setString("strikeRules", strikeRulesJSON.toString());
        repeatStrikeTab.strikeRuleEditor.loadData();
    }

    public static void addStrikeRule(String name, JSONObject scanCheck, JSONObject strikeRulesJSON) {
        strikeRulesJSON.put(name, scanCheck);
        saveStrikeRule(strikeRulesJSON);
        repeatStrikeTab.strikeRuleEditor.loadData();
        repeatStrikeTab.runSavedStrikeRuleButton.setEnabled(true);
    }

    public static void deleteStrikeRule(String name, JSONObject strikeRulesJSON) {
        strikeRulesJSON.remove(name);
        saveStrikeRule(strikeRulesJSON);
        if(strikeRulesJSON.keySet().isEmpty()) {
            repeatStrikeTab.runSavedStrikeRuleButton.setEnabled(false);
        }
        repeatStrikeTab.strikeRuleEditor.loadData();
    }

    public static void deleteAllStrikeRules() {
        saveStrikeRule(new JSONObject());
        repeatStrikeTab.strikeRuleEditor.loadData();
        repeatStrikeTab.runSavedStrikeRuleButton.setEnabled(false);
    }

    public static void scanProxyHistory(JSONObject strikeRule) {
        if(strikeRule.getString("type").equals(VulnerabilityScanType.DiffingNonAi.name())) {
            RepeatStrikeExtension.executorService.submit(() -> {
                AnalyseProxyHistory.analyseWithDiffing(strikeRule.getString("value"));
            });
        } else if(strikeRule.getString("type").equals(VulnerabilityScanType.Regex.name())) {
            RepeatStrikeExtension.executorService.submit(() -> {
                AnalyseProxyHistory.analyseWithRegex(strikeRule.getJSONObject("analysis"), strikeRule.getJSONObject("param"));
            });
        }
    }
}
