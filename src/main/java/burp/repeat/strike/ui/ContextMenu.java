package burp.repeat.strike.ui;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.InvocationType;
import burp.repeat.strike.ai.VulnerabilityAnalysis;
import burp.repeat.strike.ai.VulnerabilityScanType;
import burp.repeat.strike.settings.Settings;
import burp.repeat.strike.utils.Utils;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;

import static burp.repeat.strike.RepeatStrikeExtension.*;


public class ContextMenu implements ContextMenuItemsProvider {
    public java.util.List<Component> provideMenuItems(ContextMenuEvent event)
    {
        java.util.List<Component> menuItemList = new ArrayList<>();
        if(event.messageEditorRequestResponse().isPresent() && event.invocationType() == InvocationType.MESSAGE_EDITOR_REQUEST && event.isFromTool(ToolType.REPEATER)) {
            JMenuItem addToRepeatStrike = new JMenuItem("Add to Repeat Strike");
            addToRepeatStrike.setEnabled(requestHistory.size() < 2);
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
            JMenuItem runRepeatStrikeJava = new JMenuItem("Scan using Java ("+requestHistory.size()+")");
            runRepeatStrikeJava.setEnabled(!requestHistory.isEmpty());
            runRepeatStrikeJava.addActionListener(e -> {
                VulnerabilityAnalysis.check(requestHistory.toArray(new HttpRequest[0]), responseHistory.toArray(new HttpResponse[0]), VulnerabilityScanType.Java);
                Utils.resetHistory(false);
            });
            menuItemList.add(runRepeatStrikeJava);
            JMenuItem runRepeatStrikeRegex = new JMenuItem("Scan using Regex ("+requestHistory.size()+")");
            runRepeatStrikeRegex.setEnabled(requestHistory.size() < 2);
            runRepeatStrikeRegex.addActionListener(e -> {
                VulnerabilityAnalysis.check(requestHistory.toArray(new HttpRequest[0]), responseHistory.toArray(new HttpResponse[0]), VulnerabilityScanType.Regex);
                Utils.resetHistory(false);
            });
            menuItemList.add(runRepeatStrikeRegex);
        }

        JMenuItem resetMenu = new JMenuItem("Empty requests/responses");
        resetMenu.addActionListener(e -> Utils.resetHistory(false));
        menuItemList.add(resetMenu);

        JMenuItem settings = new JMenuItem("Settings");
        settings.addActionListener(e -> Settings.showSettingsWindow());
        menuItemList.add(settings);

        return menuItemList;
    }
}
