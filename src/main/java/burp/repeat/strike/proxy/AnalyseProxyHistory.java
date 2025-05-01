package burp.repeat.strike.proxy;

import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.repeat.strike.RepeatStrikeExtension;
import burp.repeat.strike.settings.InvalidTypeSettingException;
import burp.repeat.strike.settings.UnregisteredSettingException;
import burp.repeat.strike.utils.Utils;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.*;

import static burp.repeat.strike.RepeatStrikeExtension.api;
import static burp.repeat.strike.ai.VulnerabilityAnalysis.*;

public class AnalyseProxyHistory {
    public static void analyse(Object scanCheck, HttpRequest originalRequest) {
        try {
            boolean debugOutput;
            int maxProxyHistory;
            try {
                debugOutput = RepeatStrikeExtension.generalSettings.getBoolean("debugOutput");
                maxProxyHistory = RepeatStrikeExtension.generalSettings.getInteger("maxProxyHistory");
            } catch (UnregisteredSettingException | InvalidTypeSettingException e) {
                api.logging().logToError("Error loading settings:" + e);
                throw new RuntimeException(e);
            }

            List<ProxyHttpRequestResponse> proxyHistory = api.proxy().history();
            int proxyHistorySize = proxyHistory.size();
            int count = 0;
            int vulnCount = 0;

            Set<String> requestKeys = new HashSet<>();
            requestKeys.add(Utils.generateRequestKey(originalRequest)+"|"+originalRequest.pathWithoutQuery());
            for(int i = proxyHistorySize - 1; i >= 0; i--) {
                if(count >= maxProxyHistory) {
                    break;
                }
                ProxyHttpRequestResponse historyItem = proxyHistory.get(i);
                if(historyItem.request().parameters().isEmpty()) {
                    continue;
                }
                String requestKey = Utils.generateRequestKey(historyItem.request())+"|"+historyItem.request().pathWithoutQuery();
                if(requestKeys.contains(requestKey)) {
                    continue;
                }
                if(!historyItem.request().isInScope()) {
                    if(debugOutput) {
                        api.logging().logToOutput("Skipping url " + historyItem.request().url() + " not in scope");
                    }
                    continue;
                }
                requestKeys.add(requestKey);
                String probe = getRequestProbe(scanCheck);
                for(ParsedHttpParameter historyItemParam: historyItem.request().parameters()) {
                    if(isVulnerable(scanCheck, historyItem.response())) {
                        continue;
                    }
                    if(debugOutput) {
                        api.logging().logToOutput("Testing URL " + historyItem.request().pathWithoutQuery() + "...");
                        api.logging().logToOutput("Testing parameter " + historyItemParam.name() + "...");
                    }
                    if(conductAttack(historyItem, historyItemParam.type().toString(), historyItemParam.name(), probe, scanCheck)) {
                        if(debugOutput) {
                            api.logging().logToOutput("Found vulnerability");
                        }
                        vulnCount++;
                    }
                }
                count++;
            }
            if(debugOutput) {
                api.logging().logToOutput("Finished scanning proxy history.");
                api.logging().logToOutput("Repeat Strike found " + vulnCount + " potential vulnerabilit" + (vulnCount == 1 ? "y" : "ies"));
            }
        } catch (Throwable throwable) {
            StringWriter writer = new StringWriter();
            throwable.printStackTrace(new PrintWriter(writer));
            api.logging().logToError(writer.toString());
        }
    }

    public static boolean conductAttack(ProxyHttpRequestResponse historyItem, String paramType, String paramName, String paramValue, Object scanCheck) {
        long timeoutMs = 2000;
        HttpRequest modifiedRequest = Utils.modifyRequest(historyItem.request(), paramType, paramName, paramValue);
        if(modifiedRequest != null) {
            HttpRequestResponse requestResponse = api.http().sendRequest(modifiedRequest, RequestOptions.requestOptions().withResponseTimeout(timeoutMs));
            if(requestResponse.response() != null) {
                if (isVulnerable(scanCheck, requestResponse.response())) {
                    requestResponse.annotations().setNotes(getDescription(scanCheck));
                    api.organizer().sendToOrganizer(requestResponse);
                    return true;
                }
            }
        }
        return false;
    }
}
