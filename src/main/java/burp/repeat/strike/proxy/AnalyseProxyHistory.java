package burp.repeat.strike.proxy;

import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.ResponseVariationsAnalyzer;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.repeat.strike.RepeatStrikeExtension;
import burp.repeat.strike.diffing.DiffingAttributes;
import burp.repeat.strike.settings.InvalidTypeSettingException;
import burp.repeat.strike.settings.UnregisteredSettingException;
import burp.repeat.strike.utils.Utils;
import org.json.JSONObject;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.*;

import static burp.repeat.strike.RepeatStrikeExtension.api;
import static burp.repeat.strike.ai.VulnerabilityAnalysis.*;

public class AnalyseProxyHistory {
    public static void analyseWithRegex(JSONObject vulnerability, JSONObject param) {
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

            for(int i = proxyHistorySize - 1; i >= 0; i--) {
                if (count >= maxProxyHistory) {
                    break;
                }
                ProxyHttpRequestResponse historyItem = proxyHistory.get(i);
                if (historyItem.request().parameters().isEmpty()) {
                    continue;
                }
                if (!historyItem.request().isInScope()) {
                    continue;
                }
                String probe = vulnerability.getString("probeToUse");
                String responseRegex = vulnerability.getString("responseRegex");
                String context = vulnerability.getString("context");
                for (ParsedHttpParameter historyItemParam : historyItem.request().parameters()) {
                    if (isVulnerable(context, historyItem.response(), responseRegex)) {
                        continue;
                    }
                    if(debugOutput) {
                        api.logging().logToOutput("Testing URL " + historyItem.request().pathWithoutQuery() + "...");
                        api.logging().logToOutput("Testing parameter " + historyItemParam.name() + "...");
                    }
                    if(conductAttackUsingRegex(vulnerability, historyItem, context, historyItemParam.type().toString(), historyItemParam.name(), probe, responseRegex)) {
                        if (debugOutput) {
                            api.logging().logToOutput("Found vulnerability");
                        }
                        vulnCount++;
                    }
                }
                count++;
            }
            if (debugOutput) {
                api.logging().logToOutput("Finished scanning proxy history.");
                api.logging().logToOutput("Repeat Strike found " + vulnCount + " potential vulnerabilit" + (vulnCount == 1 ? "y" : "ies"));
            }
        } catch (Throwable throwable) {
            StringWriter writer = new StringWriter();
            throwable.printStackTrace(new PrintWriter(writer));
            api.logging().logToError(writer.toString());
        }
    }
    public static void analyseWithDiffing(String requestKey, JSONObject attackParam, HttpRequest[] requests, DiffingAttributes analysis) {
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

            for(int i = proxyHistorySize - 1; i >= 0; i--) {
                if(count >= maxProxyHistory) {
                    break;
                }
                ProxyHttpRequestResponse historyItem = proxyHistory.get(i);
                if(historyItem.finalRequest().parameters().isEmpty()) {
                    continue;
                }
                if(!historyItem.finalRequest().isInScope()) {
                    if(debugOutput) {
                        api.logging().logToOutput("Skipping url " + historyItem.finalRequest().url() + " not in scope");
                    }
                    continue;
                }
                if(requestKey.equals(Utils.generateRequestKey(historyItem.finalRequest()))) {
                    continue;
                }
                for(ParsedHttpParameter historyItemParam: historyItem.finalRequest().parameters()) {
                    if(debugOutput) {
                        api.logging().logToOutput("Testing URL " + historyItem.finalRequest().pathWithoutQuery() + "...");
                        api.logging().logToOutput("Testing parameter " + historyItemParam.name() + "...");
                    }

                    ArrayList<HttpRequestResponse> requestResponses = new ArrayList<>();
                    for(int j=0;j<requests.length;j++) {
                        HttpRequestResponse requestResponse = conductAttack(requests[j], historyItemParam.type().toString(), historyItemParam.name(), attackParam.getString("value"));
                        if(requestResponse != null) {
                            requestResponses.add(requestResponse);
                        } else {
                            break;
                        }
                    }

                    if(Utils.checkInvariantAttributes(requestResponses, analysis)) {
                        if (debugOutput) {
                            api.logging().logToOutput("Found vulnerability");
                            for(HttpRequestResponse requestResponse: requestResponses) {
                                requestResponse.annotations().setNotes(vulnCount + " - Found vulnerability using diffing scan");
                                api.organizer().sendToOrganizer(requestResponse);
                            }
                            vulnCount++;
                        }
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
    public static void analyseWithObject(Object scanCheck) {
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

            for(int i = proxyHistorySize - 1; i >= 0; i--) {
                if(count >= maxProxyHistory) {
                    break;
                }
                ProxyHttpRequestResponse historyItem = proxyHistory.get(i);
                if(historyItem.request().parameters().isEmpty()) {
                    continue;
                }
                if(!historyItem.request().isInScope()) {
                    if(debugOutput) {
                        api.logging().logToOutput("Skipping url " + historyItem.request().url() + " not in scope");
                    }
                    continue;
                }
                String[] probes = getRequestProbes(scanCheck);
                for(ParsedHttpParameter historyItemParam: historyItem.request().parameters()) {
                    if(debugOutput) {
                        api.logging().logToOutput("Testing URL " + historyItem.request().pathWithoutQuery() + "...");
                        api.logging().logToOutput("Testing parameter " + historyItemParam.name() + "...");
                    }
                    int probeSuccess = 0;
                    ArrayList<HttpRequestResponse> requestResponses = new ArrayList<>();
                    for(int probeNumber = 0; probeNumber < probes.length; probeNumber++ ) {
                        HttpRequestResponse requestResponse = conductAttackUsingObject(HttpRequestResponse.httpRequestResponse(historyItem.finalRequest(), historyItem.response()), historyItemParam.type().toString(), historyItemParam.name(), probes[probeNumber], probeNumber, scanCheck);
                        if (requestResponse != null) {
                            requestResponses.add(requestResponse);
                            probeSuccess++;
                        } else {
                            break;
                        }
                    }
                    if(probeSuccess == probes.length) {
                        if (debugOutput) {
                            api.logging().logToOutput("Found vulnerability");
                        }
                        String notes = getDescription(scanCheck);
                        for(HttpRequestResponse requestResponse: requestResponses) {
                            requestResponse.annotations().setNotes(notes);
                            api.organizer().sendToOrganizer(requestResponse);
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

    public static HttpRequestResponse conductAttack(HttpRequest request, String paramType, String paramName, String paramValue) {
        long timeoutMs = 2000;
        HttpRequest modifiedRequest = Utils.modifyRequest(request, paramType, paramName, paramValue);
        if(modifiedRequest != null) {
            return api.http().sendRequest(modifiedRequest, RequestOptions.requestOptions().withResponseTimeout(timeoutMs));
        }
        return null;
    }

    public static HttpRequestResponse conductAttackUsingObject(HttpRequestResponse httpReqResp, String paramType, String paramName, String paramValue, int probeNumber, Object scanCheck) {
        long timeoutMs = 2000;
        HttpRequest modifiedRequest = Utils.modifyRequest(httpReqResp.request(), paramType, paramName, paramValue);
        if(modifiedRequest != null) {
            HttpRequestResponse requestResponse = api.http().sendRequest(modifiedRequest, RequestOptions.requestOptions().withResponseTimeout(timeoutMs));
            if(requestResponse.response() != null) {
                if(didProbeWork(scanCheck, requestResponse.response(), probeNumber)) {
                    return requestResponse;
                }
            }
        }
        return null;
    }
    public static boolean conductAttackUsingRegex(JSONObject vulnerability, ProxyHttpRequestResponse historyItem, String context, String paramType, String paramName, String paramValue, String responseRegex) {
        HttpRequest modifiedRequest = Utils.modifyRequest(historyItem.request(), paramType, paramName, paramValue);
        if(modifiedRequest != null) {
            HttpRequestResponse requestResponse = api.http().sendRequest(modifiedRequest);
            if (requestResponse.response() != null) {
                if (isVulnerable(context, requestResponse.response(), responseRegex)) {
                    requestResponse.annotations().setNotes(vulnerability.getString("shortDescription"));
                    api.organizer().sendToOrganizer(requestResponse);
                    return true;
                }
            }
        }
        return false;
    }
}
