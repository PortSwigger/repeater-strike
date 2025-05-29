package burp.repeat.strike.ui;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.InvocationType;

import java.awt.*;
import java.util.ArrayList;

import static burp.repeat.strike.utils.Utils.buildSettingsMenu;


public class ContextMenu implements ContextMenuItemsProvider {
    private final RepeatStrikeTab repeatStrikeTab;
    public ContextMenu(RepeatStrikeTab repeatStrikeTab) {
        super();
        this.repeatStrikeTab = repeatStrikeTab;
    }
    public java.util.List<Component> provideMenuItems(ContextMenuEvent event)
    {
        java.util.List<Component> menuItemList = new ArrayList<>();
        if(event.messageEditorRequestResponse().isPresent() && event.invocationType() == InvocationType.MESSAGE_EDITOR_REQUEST && event.isFromTool(ToolType.REPEATER)) {
            menuItemList.add(ScanChecksMenus.buildAddToRepeatStrikeMenu(event, repeatStrikeTab));
        }
        menuItemList.add(buildSettingsMenu());
        return menuItemList;
    }
}
