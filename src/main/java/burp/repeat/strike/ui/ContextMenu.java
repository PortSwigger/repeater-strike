package burp.repeat.strike.ui;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.InvocationType;
import burp.repeat.strike.utils.ScanCheckUtils;
import org.json.JSONObject;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;

import static burp.repeat.strike.RepeatStrikeExtension.requestHistory;
import static burp.repeat.strike.ui.ScanChecksMenus.*;
import static burp.repeat.strike.utils.Utils.buildSettingsMenu;


public class ContextMenu implements ContextMenuItemsProvider {
    public java.util.List<Component> provideMenuItems(ContextMenuEvent event)
    {
        java.util.List<Component> menuItemList = new ArrayList<>();
        if(event.messageEditorRequestResponse().isPresent() && event.invocationType() == InvocationType.MESSAGE_EDITOR_REQUEST && event.isFromTool(ToolType.REPEATER)) {
            JSONObject scanChecksJSON = ScanCheckUtils.getSavedCustomScanChecks();
            menuItemList.add(ScanChecksMenus.buildAddToRepeatStrikeMenu(event));
            JMenu scanMenu = new JMenu("Scan " + "(" + requestHistory.size() + ")");
            scanMenu.setEnabled(!requestHistory.isEmpty());
            scanMenu.add(buildRunJavaScanMenu());
            scanMenu.add(buildRunRegexScanMenu());
            scanMenu.add(buildRunDiffingScanMenu());
            menuItemList.add(scanMenu);
            menuItemList.add(ScanChecksMenus.buildScanCheckMenu(scanChecksJSON));
            menuItemList.add(ScanChecksMenus.buildSaveLastScanCheckMenu(scanChecksJSON));
            menuItemList.add(buildResetMenu());
            menuItemList.add(buildDeleteAllScanChecksMenu(scanChecksJSON));
        }
        menuItemList.add(buildSettingsMenu());
        return menuItemList;
    }
}
