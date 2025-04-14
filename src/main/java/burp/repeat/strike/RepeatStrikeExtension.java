package burp.repeat.strike;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.EnhancedCapability;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.ui.hotkey.HotKeyContext;
import burp.repeat.strike.ai.AI;
import burp.repeat.strike.settings.Settings;
import burp.repeat.strike.utils.Utils;

import javax.swing.*;
import java.util.Set;

public class RepeatStrikeExtension implements BurpExtension, IBurpExtender, ExtensionUnloadingHandler {
    public static boolean hasHotKey = false;
    public static JFrame SettingsFrame = null;
    public static IBurpExtenderCallbacks callbacks;
    public static Settings generalSettings = null;
    public static MontoyaApi api;
    public static String extensionName = "Repeat Strike";
    public static String version = "v1.0.0";
    @Override
    public void initialize(MontoyaApi montoyaApi) {
        RepeatStrikeExtension.api = montoyaApi;
        api.extension().setName(extensionName);
        api.logging().logToOutput(extensionName+ " " + version);
        api.extension().registerUnloadingHandler(this);
        if(!AI.isAiSupported()) {
            api.logging().logToOutput("AI features are not available. This extension will not work without AI. You need to enable \"Use AI\" in the extension tab.");
        }
        api.userInterface().menuBar().registerMenu(Utils.generateMenuBar());
        Burp burp = new Burp(montoyaApi.burpSuite().version());
        if(burp.hasCapability(Burp.Capability.REGISTER_HOTKEY)) {
            Registration registration = api.userInterface().registerHotKeyHandler(HotKeyContext.HTTP_MESSAGE_EDITOR,
                    "Ctrl+Alt+R",
                    event -> {
                        if (event.messageEditorRequestResponse().isEmpty() || !AI.isAiSupported()) {
                            return;
                        }

                    });
            if (registration.isRegistered()) {
                hasHotKey = true;
                api.logging().logToOutput("Successfully registered hotkey handler");
            } else {
                api.logging().logToError("Failed to register hotkey handler");
            }
        }
    }

    @Override
    public Set<EnhancedCapability> enhancedCapabilities() {
        return Set.of(EnhancedCapability.AI_FEATURES);
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        RepeatStrikeExtension.callbacks = callbacks;
        generalSettings = new Settings("general", callbacks);
        Utils.registerGeneralSettings(generalSettings);
        generalSettings.load();
    }

    @Override
    public void extensionUnloaded() {

    }
}
