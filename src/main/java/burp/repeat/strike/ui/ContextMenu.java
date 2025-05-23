package burp.repeat.strike.ui;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.InvocationType;
import burp.repeat.strike.utils.ScanCheckUtils;
import org.json.JSONObject;

import java.awt.*;
import java.util.ArrayList;

import static burp.repeat.strike.ui.ScanChecksMenus.*;
import static burp.repeat.strike.utils.Utils.buildSettingsMenu;


public class ContextMenu implements ContextMenuItemsProvider {
    public java.util.List<Component> provideMenuItems(ContextMenuEvent event)
    {
        java.util.List<Component> menuItemList = new ArrayList<>();
        if(event.messageEditorRequestResponse().isPresent() && event.invocationType() == InvocationType.MESSAGE_EDITOR_REQUEST && event.isFromTool(ToolType.REPEATER)) {
            menuItemList.add(ScanChecksMenus.buildAddToRepeatStrikeMenu(event));
            menuItemList.add(buildRunJavaScanMenu());
            menuItemList.add(buildRunRegexScanMenu());
            menuItemList.add(buildRunDiffingScanMenu());
            JSONObject scanChecksJSON = ScanCheckUtils.getSavedCustomScanChecks();
            menuItemList.add(ScanChecksMenus.buildScanCheckMenu(scanChecksJSON));
            menuItemList.add(ScanChecksMenus.buildSaveLastScanCheckMenu(scanChecksJSON));
            menuItemList.add(buildResetMenu());
            menuItemList.add(buildDeleteAllScanChecksMenu());
        }
        menuItemList.add(buildSettingsMenu());
        return menuItemList;
    }
}
