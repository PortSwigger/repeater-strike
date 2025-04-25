package burp.repeat.strike.ai;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.repeat.strike.RepeatStrikeExtension;
import burp.repeat.strike.settings.InvalidTypeSettingException;
import burp.repeat.strike.settings.UnregisteredSettingException;
import burp.repeat.strike.utils.FetchUtils;
import burp.repeat.strike.utils.Utils;
import org.json.JSONObject;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.*;

import static burp.repeat.strike.RepeatStrikeExtension.api;

public class AnalyseProxyHistory {
    public static void analyse(JSONObject vulnerability, JSONObject criteria, JSONObject param, HttpRequest originalRequest, HttpResponse originalResponse) {
        RepeatStrikeExtension.executorService.submit(() -> {
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
                boolean isOriginalRequestADocument = criteria.getString("type").equalsIgnoreCase("document");

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
                        continue;
                    }
                    if(isOriginalRequestADocument) {
                        if(!FetchUtils.isDocument(historyItem.request())) {
                            continue;
                        }
                    } else {
                        if(FetchUtils.isDocument(historyItem.request())) {
                            continue;
                        }
                    }
                    requestKeys.add(requestKey);
                    for(ParsedHttpParameter historyItemParam: historyItem.request().parameters()) {
                        if(!historyItemParam.type().toString().equalsIgnoreCase(param.getString("type"))) {
                            continue;
                        }
                        String probe = vulnerability.getString("probeToUse");
                        String responseRegex = vulnerability.getString("responseRegex");
                        String context = vulnerability.getString("context");
                        if(Utils.isVulnerable(context, historyItem.response(), responseRegex)) {
                            continue;
                        }
                        boolean didRepeatAttackWork = conductAttack(historyItem, context, param.getString("type"), param.getString("name"), param.getString("value"), responseRegex);
                        if(!didRepeatAttackWork) {
                            boolean didDifferentParamWork = conductAttack(historyItem, context, param.getString("type"), historyItemParam.name(), param.getString("value"), responseRegex);
                            if(!didDifferentParamWork) {
                                conductAttack(historyItem, context, historyItemParam.type().toString(), historyItemParam.name(), probe, responseRegex);
                            }
                        }
                    }
                    count++;
                }
                if(debugOutput) {
                    api.logging().logToOutput("Finished scanning proxy history.");
                }
            } catch (Throwable throwable) {
                StringWriter writer = new StringWriter();
                throwable.printStackTrace(new PrintWriter(writer));
                api.logging().logToError(writer.toString());
            }
        });
    }

    public static boolean conductAttack(ProxyHttpRequestResponse historyItem, String context, String paramType, String paramName, String paramValue, String responseRegex) {
        HttpRequest modifiedRequest = Utils.modifyRequest(historyItem.request(), paramType, paramName, paramValue);
        if(modifiedRequest != null) {
            HttpRequestResponse requestResponse = api.http().sendRequest(modifiedRequest);
            if(requestResponse.response() != null) {
                if (Utils.isVulnerable(context, requestResponse.response(), responseRegex)) {
                    String notes = NotesGenerator.generateNotes(context, paramType, paramName, paramValue, requestResponse.request(), requestResponse.response());
                    requestResponse.annotations().setNotes(notes);
                    api.organizer().sendToOrganizer(requestResponse);
                    return true;
                }
            }
        }
        return false;
    }
}
