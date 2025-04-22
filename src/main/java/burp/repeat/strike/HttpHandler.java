package burp.repeat.strike;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.repeat.strike.ai.AI;
import burp.repeat.strike.ai.VulnerabilityAnalysis;
import burp.repeat.strike.settings.InvalidTypeSettingException;
import burp.repeat.strike.settings.UnregisteredSettingException;
import burp.repeat.strike.utils.Utils;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;

import static burp.repeat.strike.RepeatStrikeExtension.api;
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
        String requestKey = Utils.generateRequestKey(req);
        if(!requestHistoryPos.containsKey(requestKey)) {
            requestHistoryPos.put(requestKey, 1);
            requestHistory.put(requestKey, new ArrayList<>());
            responseHistory.put(requestKey, new ArrayList<>());
        }
        if(toolSource.isFromTool(ToolType.REPEATER) && req.isInScope()) {
            boolean debugOutput;
            try {
                debugOutput = RepeatStrikeExtension.generalSettings.getBoolean("debugOutput");
            } catch (UnregisteredSettingException | InvalidTypeSettingException e) {
                api.logging().logToError("Error loading settings:" + e);
                throw new RuntimeException(e);
            }
            responseHistory.get(requestKey).add(resp);
            requestHistory.get(requestKey).add(req);
            requestHistoryPos.put(requestKey, requestHistoryPos.get(requestKey)+1);
            JSONArray headersAndParameters = RequestDiffer.generateHeadersAndParametersJson(requestHistory.get(requestKey).toArray(new HttpRequest[0]));
            if(debugOutput) {
                api.logging().logToOutput("Analysing parameters:" + headersAndParameters);
            }
            if(!headersAndParameters.isEmpty()) {
                JSONObject lastParamObject = headersAndParameters.getJSONObject(headersAndParameters.length()- 1);
                VulnerabilityAnalysis.check(req, resp, lastParamObject);
                Utils.resetHistory(requestKey, false);
            }
        }
        return null;
    }
}
