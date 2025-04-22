package burp.repeat.strike.ai;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.repeat.strike.RepeatStrikeExtension;
import burp.repeat.strike.settings.InvalidTypeSettingException;
import burp.repeat.strike.settings.UnregisteredSettingException;
import burp.repeat.strike.utils.Utils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.*;
import java.util.stream.Collectors;

import static burp.repeat.strike.RepeatStrikeExtension.api;

public class AnalyseProxyHistory {
    public static void analyse(JSONObject param, HttpRequest originalRequest, HttpResponse originalResponse) {
        RepeatStrikeExtension.executorService.submit(() -> {
            try {
                boolean debugAi;
                boolean debugOutput;
                int maxProxyHistory;
                try {
                    debugOutput = RepeatStrikeExtension.generalSettings.getBoolean("debugOutput");
                    debugAi = RepeatStrikeExtension.generalSettings.getBoolean("debugAi");
                    maxProxyHistory = RepeatStrikeExtension.generalSettings.getInteger("maxProxyHistory");
                } catch (UnregisteredSettingException | InvalidTypeSettingException e) {
                    api.logging().logToError("Error loading settings:" + e);
                    throw new RuntimeException(e);
                }

                List<ProxyHttpRequestResponse> proxyHistory = api.proxy().history();
                int proxyHistorySize = proxyHistory.size();
                HashMap<Integer, ArrayList<String>> selectedProxyHistory = new HashMap<>();
                int count = 0;
                for(int i = proxyHistorySize - 1; i >= 0; i--) {
                    if(count >= maxProxyHistory) {
                        break;
                    }
                    ProxyHttpRequestResponse historyItem = proxyHistory.get(i);
                    if(!originalResponse.mimeType().equals(historyItem.mimeType())) {
                        continue;
                    }
                    if(Utils.generateRequestKey(historyItem.request()).equals(Utils.generateRequestKey(originalRequest)) && historyItem.request().pathWithoutQuery().equals(originalRequest.pathWithoutQuery())) {
                        continue;
                    }
                    if(!historyItem.request().isInScope()) {
                        continue;
                    }
                    selectedProxyHistory.put(i, historyItem.request().parameters().stream().map(ParsedHttpParameter::name)
                            .collect(Collectors.toCollection(ArrayList::new)));
                    count++;
                }

                ArrayList<String> paramNames = new ArrayList<>();
                for (Map.Entry<Integer, ArrayList<String>> entry : selectedProxyHistory.entrySet()) {
                    paramNames.addAll(entry.getValue());
                }
                paramNames = new ArrayList<>(new LinkedHashSet<>(paramNames));
                AI ai = new AI();
                ai.setBypassRateLimit(true);
                ai.setSystemMessage("""
                    Do not output markdown. Output as plain text separate by new lines.
                    Loop through these parameter names and find ones similar to\s""" + param.getString("name") + """
                     then return them as text separated by new lines
                 """);

                ai.setPrompt(String.join("\n", paramNames));
                ai.setTemperature(1.0);
                if(debugAi) {
                    api.logging().logToOutput("Sending information to the AI:");
                    api.logging().logToOutput(ai.getSystemMessage()+ai.getPrompt());
                }
                String[] similarParamNames = ai.execute().split("\n");
                if(debugAi) {
                    api.logging().logToOutput("Response from the AI:" + String.join("\n", similarParamNames));
                }
                for (String similarParamName : similarParamNames) {
                    for (Map.Entry<Integer, ArrayList<String>> entry : selectedProxyHistory.entrySet()) {
                        if (entry.getValue().contains(similarParamName)) {
                            ProxyHttpRequestResponse historyItem = proxyHistory.get(entry.getKey());
                            HttpRequest modifiedRequest = Utils.modifyRequest(historyItem.request(), param.getString("type"), similarParamName, param.getString("value"));
                            if(modifiedRequest != null) {
                                HttpRequestResponse requestResponse = api.http().sendRequest(modifiedRequest);
                                if(LooksLikeVulnerability.didAttackWork(requestResponse.request().toString(), requestResponse.response().toString())) {
                                    String name = RepeaterNamer.generateName(requestResponse.request().toString(), requestResponse.response().toString());
                                    api.repeater().sendToRepeater(requestResponse.request(), name);
                                }
                            }
                        }
                    }
                }
            } catch (Throwable throwable) {
                StringWriter writer = new StringWriter();
                throwable.printStackTrace(new PrintWriter(writer));
                api.logging().logToError(writer.toString());
            }
        });
    }
}
