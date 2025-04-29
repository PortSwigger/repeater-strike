package burp.repeat.strike.handlers;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.repeat.strike.RepeatStrikeExtension;
import burp.repeat.strike.ai.AI;
import burp.repeat.strike.ai.VulnerabilityAnalysis;
import burp.repeat.strike.settings.InvalidTypeSettingException;
import burp.repeat.strike.settings.UnregisteredSettingException;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;

import static burp.repeat.strike.RepeatStrikeExtension.api;

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
        if(toolSource.isFromTool(ToolType.REPEATER) && req.isInScope()) {
            boolean debugOutput;
            boolean autoInvoke;
            try {
                debugOutput = RepeatStrikeExtension.generalSettings.getBoolean("debugOutput");
                autoInvoke = RepeatStrikeExtension.generalSettings.getBoolean("autoInvoke");
            } catch (UnregisteredSettingException | InvalidTypeSettingException e) {
                api.logging().logToError("Error loading settings:" + e);
                throw new RuntimeException(e);
            }
            if(autoInvoke) {
                VulnerabilityAnalysis.check(req, resp);
            }
        }
        return null;
    }
}
