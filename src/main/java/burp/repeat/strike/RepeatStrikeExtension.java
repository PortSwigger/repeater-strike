package burp.repeat.strike;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.EnhancedCapability;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.settings.*;
import burp.repeat.strike.ai.AI;
import burp.repeat.strike.http.HttpHandler;
import burp.repeat.strike.ui.ContextMenu;
import burp.repeat.strike.ui.RepeatStrikePanel;
import burp.repeat.strike.ui.RepeatStrikeTab;

import java.util.ArrayList;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class RepeatStrikeExtension implements BurpExtension, ExtensionUnloadingHandler {
    public static MontoyaApi api;
    public static String extensionName = "Repeat Strike";
    public static String version = "v1.0.0";
    public static ArrayList<HttpRequest> requestHistory = new ArrayList<>();
    public static ArrayList<HttpResponse> responseHistory = new ArrayList<>();
    public static final ExecutorService executorService = Executors.newSingleThreadExecutor();
    public static RepeatStrikeTab repeatStrikeTab;
    public static RepeatStrikePanel repeatStrikePanel;
    public static boolean hasShutDown = false;
    public static SettingsPanelWithData settings;
    @Override
    public void initialize(MontoyaApi montoyaApi) {
        RepeatStrikeExtension.api = montoyaApi;
        api.extension().setName(extensionName);
        api.logging().logToOutput(extensionName+ " " + version);
        api.extension().registerUnloadingHandler(this);
        if(!AI.isAiSupported()) {
            api.logging().logToOutput("AI features are not available. This extension will not work without AI. You need to enable \"Use AI\" in the extension tab.");
        }
        repeatStrikeTab = new RepeatStrikeTab(api.userInterface());
        api.userInterface().registerContextMenuItemsProvider(new ContextMenu(repeatStrikeTab));
        repeatStrikePanel = new RepeatStrikePanel(repeatStrikeTab);
        api.userInterface().registerSuiteTab(extensionName, repeatStrikePanel);
        if(repeatStrikeTab.getWordList().length > 0) {
            repeatStrikePanel.setWordListWarning(repeatStrikeTab.wordListWarning);
        }

        api.http().registerHttpHandler(new HttpHandler());
        settings = SettingsPanelBuilder.settingsPanel()
                .withPersistence(SettingsPanelPersistence.USER_SETTINGS)
                .withTitle("Repeat Strike Settings")
                .withDescription("""                       
                        Auto invoke - Allows you to execute Repeat Strike on every Repeater request sent.
                        Debug output - Outputs debug information to the console.
                        Debug AI - Make Repeat Strike log all AI requests and responses to the console.
                        Max proxy history - Controls the maximum amount of proxy history to scan.
                        Max image response limit - Controls the maximum length limit of image responses sent to the AI.
                        Max request limit - Controls the maximum length limit of requests sent to the AI.
                        Max response limit - Controls the maximum length limit of requests sent to the AI.
                        """)
                .withKeywords("Repeater", "Repeat", "Strike")
                .withSettings(
                        SettingsPanelSetting.booleanSetting("Auto invoke", false),
                        SettingsPanelSetting.booleanSetting("Debug output", false),
                        SettingsPanelSetting.booleanSetting("Debug AI", false),
                        SettingsPanelSetting.integerSetting("Max proxy history", 25000),
                        SettingsPanelSetting.integerSetting("Max image response limit", 1000),
                        SettingsPanelSetting.integerSetting("Max request limit", 100000),
                        SettingsPanelSetting.integerSetting("Max response limit", 100000)
                )
                .build();
        api.userInterface().registerSettingsPanel(settings);
    }

    @Override
    public Set<EnhancedCapability> enhancedCapabilities() {
        return Set.of(EnhancedCapability.AI_FEATURES);
    }

    @Override
    public void extensionUnloaded() {
        executorService.shutdown();
        hasShutDown = true;
        api.logging().logToOutput("Extension unloaded");
    }
}
