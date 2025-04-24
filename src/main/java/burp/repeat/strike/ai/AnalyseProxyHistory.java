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
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.*;
import java.util.stream.Collectors;

import static burp.repeat.strike.RepeatStrikeExtension.api;

public class AnalyseProxyHistory {
    public static void analyse(JSONObject vulnerability, JSONObject criteria, JSONObject param, HttpRequest originalRequest, HttpResponse originalResponse) {
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
                boolean isOriginalRequestADocument = criteria.getString("type").equalsIgnoreCase("document");

                Set<String> requestKeys = new HashSet<>();
                //requestKeys.add(Utils.generateRequestKey(originalRequest)+"|"+originalRequest.pathWithoutQuery());
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
                JSONObject paramNameJson = new JSONObject();
                paramNameJson.put("name", param.getString("name"));
                ai.setSystemMessage("""
                    Do not output markdown. Output as plain text separate by new lines.
                    Loop through these parameter names and find ones similar to\s""" + paramNameJson + """
                     then return them as JSON array
                 """);
                JSONArray paramNamesJson = new JSONArray(paramNames);
                ai.setPrompt("Param names:"+paramNamesJson);
                ai.setTemperature(1.0);
                if(debugAi) {
                    api.logging().logToOutput("Sending information to the AI:");
                    api.logging().logToOutput(ai.getSystemMessage()+ai.getPrompt());
                }
                JSONArray similarParamNames = new JSONArray(ai.execute());
                if(debugAi) {
                    api.logging().logToOutput("Response from the AI:" + similarParamNames);
                }
                for (int i=0; i<similarParamNames.length(); i++) {
                    for (Map.Entry<Integer, ArrayList<String>> entry : selectedProxyHistory.entrySet()) {
                        String similarParamName = similarParamNames.getString(i);
                        if (entry.getValue().contains(similarParamName)) {
                            ProxyHttpRequestResponse historyItem = proxyHistory.get(entry.getKey());
                            String probe = vulnerability.getString("probeToUse");
                            String responseRegex = vulnerability.getString("responseRegex");
                            HttpRequest modifiedRequest = Utils.modifyRequest(historyItem.request(), param.getString("type"), similarParamName, probe);
                            if(modifiedRequest != null) {
                                HttpRequestResponse requestResponse = api.http().sendRequest(modifiedRequest);
                                if(Utils.isVulnerable(requestResponse.response(), responseRegex)) {
                                    String notes = NotesGenerator.generateNotes(requestResponse.request(), requestResponse.response());
                                    requestResponse.annotations().setNotes(notes);
                                    api.organizer().sendToOrganizer(requestResponse);
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
