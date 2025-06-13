package burp.repeat.strike.proxy;

import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.repeat.strike.RepeatStrikeExtension;
import burp.repeat.strike.settings.InvalidTypeSettingException;
import burp.repeat.strike.settings.UnregisteredSettingException;
import burp.repeat.strike.utils.Utils;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.*;
import java.util.List;

import static burp.repeat.strike.RepeatStrikeExtension.*;
import static burp.repeat.strike.ai.VulnerabilityAnalysis.*;

public class AnalyseProxyHistory {

    @FunctionalInterface
    public interface ParamAnalysisCallback {
        void analyse(HttpRequest baseRequest, HttpResponse baseResponse, ParsedHttpParameter param, ProxyHttpRequestResponse historyItem) throws UnregisteredSettingException, InvalidTypeSettingException;
    }

    public static void analyse(ParamAnalysisCallback callback) {
        repeatStrikePanel.setStatus("Scanning proxy history...", false);
        Set<String> requestKeys = new HashSet<>();
        try {
            boolean debugOutput;
            int maxProxyHistory;
            debugOutput = RepeatStrikeExtension.generalSettings.getBoolean("debugOutput");
            maxProxyHistory = RepeatStrikeExtension.generalSettings.getInteger("maxProxyHistory");
            List<ProxyHttpRequestResponse> proxyHistory = api.proxy().history();
            int proxyHistorySize = proxyHistory.size();
            int count = 0;
            for (int i = proxyHistorySize - 1; i >= 0; i--) {
                if (count >= maxProxyHistory || hasShutDown) break;

                ProxyHttpRequestResponse item = proxyHistory.get(i);
                HttpRequest request = item.finalRequest();
                HttpResponse response = item.response();
                String requestKey = Utils.generateRequestKey(request);

                if(requestKeys.contains(requestKey)) {
                    continue;
                }

                if (!request.isInScope()) continue;

                if (debugOutput) {
                    api.logging().logToOutput("Testing URL " + request.path() + "...");
                }
                callback.analyse(request, response, null, item);
                requestKeys.add(requestKey);
                if(request.parameters().isEmpty()) {
                    continue;
                }
                for (ParsedHttpParameter param : request.parameters()) {
                    if (debugOutput) {
                        api.logging().logToOutput("Testing URL " + request.path() + "...");
                        api.logging().logToOutput("Testing parameter name" + param.name() + "...");
                    }
                    callback.analyse(request, response, param, item);
                }
                count++;
            }

            if (debugOutput) {
                api.logging().logToOutput("Finished scanning proxy history.");
            }
        } catch (Throwable t) {
            StringWriter writer = new StringWriter();
            t.printStackTrace(new PrintWriter(writer));
            api.logging().logToError(writer.toString());
        } finally {
            requestKeys.clear();
        }
    }

    public static void analyseWithRegex(JSONObject analysis, JSONObject param) throws UnregisteredSettingException, InvalidTypeSettingException {
        final boolean debugOutput = RepeatStrikeExtension.generalSettings.getBoolean("debugOutput");

        final String vulnClass = param.getString("vulnerabilityClass");

        final int[] vulnCount = {0};
        analyse((request, response, historyParam, item) -> {
            final String paramType = historyParam == null ? "path" : historyParam.type().name();
            final String paramName = historyParam == null ? "foo" : historyParam.name();

            JSONArray mutatedProbes = analysis.getJSONArray("mutatedProbesToUse");
            JSONArray mutatedResponsesRegexes = analysis.getJSONArray("mutatedResponsesRegexes");
            JSONArray originalResponseRegexes = analysis.getJSONArray("responseRegexes");
            if(tryProbes(mutatedProbes, mutatedResponsesRegexes, request, response, vulnClass, paramType, paramName, true, false, originalResponseRegexes)) {
                if (debugOutput) api.logging().logToOutput("Found vulnerability");
                vulnCount[0]++;
            }
        });

        outputVulCount(vulnCount[0]);
    }

    public static void analyseWithDiffing(String attackValue) throws UnregisteredSettingException, InvalidTypeSettingException {
        final int[] vulnCount = {0};
        final boolean debugOutput = RepeatStrikeExtension.generalSettings.getBoolean("debugOutput");

        analyse((request, response, historyParam, item) -> {
            ArrayList<HttpRequestResponse> baseResponses = Utils.getBaseResponses(request, historyParam.type().name(), historyParam.name());
            if(baseResponses != null) {
                String baseFingerprint = Utils.getBaseFingerprint(baseResponses);
                if (Utils.checkForDifferences(request, baseFingerprint, baseResponses, historyParam.type().name(), historyParam.name(), attackValue, true)) {
                    vulnCount[0]++;
                }
            }
        });

        outputVulCount(vulnCount[0]);
    }

    public static void outputVulCount(int vulnCount) {
        String vulnMessage = "Repeat Strike found " + vulnCount + " potential vulnerabilit" + (vulnCount == 1 ? "y" : "ies");
        repeatStrikePanel.setStatus(vulnMessage, false);
        api.logging().logToOutput(vulnMessage);
    }

    public static HttpRequestResponse makeRequest(HttpRequest request, String paramType, String paramName, String paramValue) throws UnregisteredSettingException, InvalidTypeSettingException {
        final boolean debugOutput = RepeatStrikeExtension.generalSettings.getBoolean("debugOutput");
        long timeoutMs = 10000;
        HttpRequest modifiedRequest = Utils.modifyRequest(request, paramType, paramName, paramValue);
        modifiedRequest = Utils.modifyRequest(modifiedRequest, "HEADER", "Connection", "close");
        if (modifiedRequest != null) {
            if(debugOutput) {
                api.logging().logToOutput("Conducting attack:" + paramValue);
            }
            return api.http().sendRequest(modifiedRequest, RequestOptions.requestOptions().withResponseTimeout(timeoutMs));
        }
        return null;
    }
}

