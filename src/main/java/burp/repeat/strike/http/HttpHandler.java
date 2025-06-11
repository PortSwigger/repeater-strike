package burp.repeat.strike.http;

import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.repeat.strike.RepeatStrikeExtension;
import burp.repeat.strike.ai.AI;
import burp.repeat.strike.ai.VulnerabilityAnalysis;
import burp.repeat.strike.ai.VulnerabilityScanType;
import burp.repeat.strike.settings.InvalidTypeSettingException;
import burp.repeat.strike.settings.UnregisteredSettingException;

import static burp.repeat.strike.RepeatStrikeExtension.*;

public class HttpHandler implements burp.api.montoya.http.handler.HttpHandler {
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent req) {
        return null;
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived resp) {
        if(!AI.isAiSupported()) {
            return null;
        }
        ToolSource toolSource = resp.toolSource();
        HttpRequest req = resp.initiatingRequest();
        if(toolSource.isFromTool(ToolType.REPEATER)) {
            boolean autoInvoke;
            boolean debugOutput;
            try {
                autoInvoke = RepeatStrikeExtension.generalSettings.getBoolean("autoInvoke");
                debugOutput = RepeatStrikeExtension.generalSettings.getBoolean("debugOutput");
                if(autoInvoke) {
                    VulnerabilityAnalysis.generateScanCheck(new HttpRequest[]{req}, new HttpResponse[]{resp}, VulnerabilityScanType.Regex, false);
                    if(debugOutput) {
                        api.logging().logToOutput("Generating scan check for Repeater request");
                    }
                }
            } catch (UnregisteredSettingException | InvalidTypeSettingException e) {
                api.logging().logToError("Error loading settings:" + e);
                throw new RuntimeException(e);
            }
        }
        return null;
    }
}
