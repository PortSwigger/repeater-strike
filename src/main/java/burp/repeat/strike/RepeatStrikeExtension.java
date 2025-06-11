package burp.repeat.strike;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.EnhancedCapability;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.repeat.strike.ai.AI;
import burp.repeat.strike.http.HttpHandler;
import burp.repeat.strike.settings.Settings;
import burp.repeat.strike.ui.ContextMenu;
import burp.repeat.strike.ui.RepeatStrikePanel;
import burp.repeat.strike.ui.RepeatStrikeTab;
import burp.repeat.strike.utils.Utils;
import org.json.JSONObject;

import javax.swing.*;
import java.util.ArrayList;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class RepeatStrikeExtension implements BurpExtension, IBurpExtender, ExtensionUnloadingHandler {
    public static JFrame SettingsFrame = null;
    public static IBurpExtenderCallbacks callbacks;
    public static Settings generalSettings = null;
    public static MontoyaApi api;
    public static String extensionName = "Repeat Strike";
    public static String version = "v1.0.0";
    public static ArrayList<HttpRequest> requestHistory = new ArrayList<>();
    public static ArrayList<HttpResponse> responseHistory = new ArrayList<>();
    public static final ExecutorService executorService = Executors.newSingleThreadExecutor();
    public static RepeatStrikeTab repeatStrikeTab;
    public static RepeatStrikePanel repeatStrikePanel;
    public static boolean hasShutDown = false;
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
        repeatStrikeTab = new RepeatStrikeTab(api.userInterface());
        api.userInterface().registerContextMenuItemsProvider(new ContextMenu(repeatStrikeTab));
        repeatStrikePanel = new RepeatStrikePanel(repeatStrikeTab);
        api.userInterface().registerSuiteTab(extensionName, repeatStrikePanel);
        api.http().registerHttpHandler(new HttpHandler());
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
        executorService.shutdown();
        hasShutDown = true;
        api.logging().logToOutput("Extension unloaded");
    }
}
