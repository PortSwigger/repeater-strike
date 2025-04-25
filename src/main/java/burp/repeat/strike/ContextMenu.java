package burp.repeat.strike;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.repeat.strike.ai.VulnerabilityAnalysis;
import burp.repeat.strike.settings.Settings;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;

import static burp.repeat.strike.RepeatStrikeExtension.api;

public class ContextMenu implements ContextMenuItemsProvider {
    public java.util.List<Component> provideMenuItems(ContextMenuEvent event)
    {
        java.util.List<Component> menuItemList = new ArrayList<>();
        JMenuItem doRepeatStrike = new JMenuItem("Do Repeat Strike");
        doRepeatStrike.addActionListener(e -> {
            if(event.messageEditorRequestResponse().isPresent()) {
                HttpRequest req = event.messageEditorRequestResponse().get().requestResponse().request();
                HttpResponse resp = event.messageEditorRequestResponse().get().requestResponse().response();
                if (req == null || resp == null) {
                    return;
                }
                VulnerabilityAnalysis.check(req, resp);
            }
        });
        menuItemList.add(doRepeatStrike);
        JMenuItem settings = new JMenuItem("Settings");
        settings.addActionListener(e -> Settings.showSettingsWindow());
        menuItemList.add(settings);

        return menuItemList;
    }
}
