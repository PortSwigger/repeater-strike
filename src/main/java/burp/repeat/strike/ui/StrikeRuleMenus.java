package burp.repeat.strike.ui;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.repeat.strike.ai.VulnerabilityAnalysis;
import burp.repeat.strike.ai.VulnerabilityScanType;
import burp.repeat.strike.utils.StrikeRulesUtils;
import org.json.JSONObject;

import javax.swing.*;


import static burp.repeat.strike.RepeatStrikeExtension.*;
import static burp.repeat.strike.utils.Utils.alert;

public class StrikeRuleMenus {

    public static JMenuItem buildSendToRepeatStrikeMenu(ContextMenuEvent event, RepeatStrikeTab repeatStrikeTab) {
        JMenuItem sendToRepeatStrike = new JMenuItem("Send to Repeater Strike");
        sendToRepeatStrike.addActionListener(e -> {
            if (event.messageEditorRequestResponse().isPresent()) {
                HttpRequest req = event.messageEditorRequestResponse().get().requestResponse().request();
                HttpResponse resp = event.messageEditorRequestResponse().get().requestResponse().response();
                if (req == null || resp == null) {
                    alert("Repeater Strike requires a request and response.");
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
        return sendToRepeatStrike;
    }

    public static JMenuItem buildRunDiffingScanMenu(){
        JMenuItem runRepeatStrikeDiffing = new JMenuItem("Using Diffing Non-AI");
        runRepeatStrikeDiffing.setEnabled(requestHistory.size() > 1);
        runRepeatStrikeDiffing.addActionListener(e -> {
            VulnerabilityAnalysis.generateStrikeRule(requestHistory.toArray(new HttpRequest[0]), responseHistory.toArray(new HttpResponse[0]), VulnerabilityScanType.DiffingNonAi, true);
        });
        return runRepeatStrikeDiffing;
    }

    public static JMenuItem buildRunRegexScanMenu() {
        JMenuItem runRepeatStrikeRegex = new JMenuItem("Using AI Regex");
        runRepeatStrikeRegex.setEnabled(!requestHistory.isEmpty());
        runRepeatStrikeRegex.addActionListener(e -> {
            VulnerabilityAnalysis.generateStrikeRule(requestHistory.toArray(new HttpRequest[0]), responseHistory.toArray(new HttpResponse[0]), VulnerabilityScanType.Regex, true);
        });
        return runRepeatStrikeRegex;
    }

    public static JMenuItem buildRunJavaScanMenu() {
        JMenuItem runRepeatStrikeJava = new JMenuItem("Using AI Java");
        runRepeatStrikeJava.setEnabled(!requestHistory.isEmpty());
        runRepeatStrikeJava.addActionListener(e -> {
            VulnerabilityAnalysis.generateStrikeRule(requestHistory.toArray(new HttpRequest[0]), responseHistory.toArray(new HttpResponse[0]), VulnerabilityScanType.Java, true);
        });
        return runRepeatStrikeJava;
    }

    public static JPopupMenu buildStrikeRuleMenu(JSONObject strikeRuleJSON) {
        JPopupMenu savedStrikeRules = new JPopupMenu();
        if(!strikeRuleJSON.isEmpty()) {
            strikeRuleJSON.keySet().stream().sorted().forEach(key -> {
                JMenuItem runStrikeRule = new JMenuItem(key);
                runStrikeRule.addActionListener(e -> {
                    JSONObject strikeRule = strikeRuleJSON.getJSONObject(key);
                    StrikeRulesUtils.scanProxyHistory(strikeRule);
                });
                savedStrikeRules.add(runStrikeRule);
            });
        }
        return savedStrikeRules;
    }
}
