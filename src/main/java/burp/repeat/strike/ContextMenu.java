package burp.repeat.strike;

import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.repeat.strike.settings.Settings;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;

public class ContextMenu implements ContextMenuItemsProvider {
    public java.util.List<Component> provideMenuItems(ContextMenuEvent event)
    {
        java.util.List<Component> menuItemList = new ArrayList<>();
        JMenuItem settings = new JMenuItem("Settings");
        settings.addActionListener(e -> Settings.showSettingsWindow());
        menuItemList.add(settings);

        return menuItemList;
    }
}
