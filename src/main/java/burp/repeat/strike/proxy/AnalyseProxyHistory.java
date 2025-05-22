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
import org.json.JSONObject;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.*;

import static burp.repeat.strike.RepeatStrikeExtension.api;
import static burp.repeat.strike.ai.VulnerabilityAnalysis.*;

public class AnalyseProxyHistory {

    @FunctionalInterface
    public interface ParamAnalysisCallback {
        void analyse(HttpRequest baseRequest, HttpResponse baseResponse, ParsedHttpParameter param, ProxyHttpRequestResponse historyItem);
    }

    public static void analyse(ParamAnalysisCallback callback) {
        try {
            boolean debugOutput;
            int maxProxyHistory;
            debugOutput = RepeatStrikeExtension.generalSettings.getBoolean("debugOutput");
            maxProxyHistory = RepeatStrikeExtension.generalSettings.getInteger("maxProxyHistory");

            List<ProxyHttpRequestResponse> proxyHistory = api.proxy().history();
            int proxyHistorySize = proxyHistory.size();
            int count = 0;

            for (int i = proxyHistorySize - 1; i >= 0; i--) {
                if (count >= maxProxyHistory) break;

                ProxyHttpRequestResponse item = proxyHistory.get(i);
                HttpRequest request = item.finalRequest();
                HttpResponse response = item.response();

                if (request.parameters().isEmpty() || !request.isInScope()) continue;

                for (ParsedHttpParameter param : request.parameters()) {
                    if (debugOutput) {
                        api.logging().logToOutput("Testing URL " + request.pathWithoutQuery() + "...");
                        api.logging().logToOutput("Testing parameter " + param.name() + "...");
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
        }
    }

    public static void analyseWithRegex(JSONObject analysis, JSONObject param, HttpRequest originalRequest) throws UnregisteredSettingException, InvalidTypeSettingException {
        Set<String> requestKeys = new HashSet<>();
        requestKeys.add(Utils.generateRequestKey(originalRequest));
        final boolean debugOutput = RepeatStrikeExtension.generalSettings.getBoolean("debugOutput");

        final String vulnClass = param.getString("vulnerabilityClass");

        final int[] vulnCount = {0};
        analyse((request, response, historyParam, item) -> {
            String requestKey = Utils.generateRequestKey(request);
            if (requestKeys.contains(requestKey)) return;
            if (isVulnerable(analysis, request, vulnClass, historyParam.type().name(), historyParam.name(), true)) {
                if (debugOutput) api.logging().logToOutput("Found vulnerability");
                vulnCount[0]++;
            }
            requestKeys.add(requestKey);
        });

        if (debugOutput) {
            api.logging().logToOutput("Repeat Strike found " + vulnCount[0] + " potential vulnerabilit" + (vulnCount[0] == 1 ? "y" : "ies"));
        }
    }

    public static void analyseWithDiffing(JSONObject originalParam, HttpRequest originalRequest, short expectedStatusCode, String attackValue) throws UnregisteredSettingException, InvalidTypeSettingException {
        final int[] vulnCount = {0};
        final boolean debugOutput = RepeatStrikeExtension.generalSettings.getBoolean("debugOutput");

        analyse((request, response, historyParam, item) -> {
            if (originalRequest.pathWithoutQuery().equals(request.pathWithoutQuery()) &&
                    originalParam.getString("type").equalsIgnoreCase(historyParam.type().toString()) &&
                    originalParam.getString("name").equalsIgnoreCase(historyParam.name())) {
                if (debugOutput) api.logging().logToOutput("Skipping duplicate parameter match.");
                return;
            }

            if (item.response() != null && item.response().statusCode() == expectedStatusCode) return;

            HttpRequestResponse rr = makeRequest(request, historyParam.type().toString(), historyParam.name(), attackValue);
            if (rr != null && rr.response().statusCode() == expectedStatusCode) {
                HttpRequestResponse baseRR = HttpRequestResponse.httpRequestResponse(request, item.response());
                baseRR.annotations().setNotes(vulnCount[0] + " - Base request");
                rr.annotations().setNotes(vulnCount[0] + " - Attack found using diffing");
                api.organizer().sendToOrganizer(baseRR);
                api.organizer().sendToOrganizer(rr);
                vulnCount[0]++;
            }
        });

        if (debugOutput) {
            outputVulCount(vulnCount[0]);
        }
    }

    public static void analyseWithObject(Object scanCheck) throws UnregisteredSettingException, InvalidTypeSettingException {
        final int[] vulnCount = {0};
        final boolean debugOutput = RepeatStrikeExtension.generalSettings.getBoolean("debugOutput");

        analyse((request, response, historyParam, item) -> {
            String[] probes = getRequestProbes(scanCheck);
            int probeSuccess = 0;
            ArrayList<HttpRequestResponse> responses = new ArrayList<>();

            for (int i = 0; i < probes.length; i++) {
                HttpRequestResponse rr = makeRequestAndVerifyUsingObject(HttpRequestResponse.httpRequestResponse(request, response),
                        historyParam.type().toString(), historyParam.name(), probes[i], i, scanCheck);
                if (rr != null) {
                    responses.add(rr);
                    probeSuccess++;
                } else break;
            }

            if (probeSuccess == probes.length) {
                String notes = getDescription(scanCheck);
                for (HttpRequestResponse rr : responses) {
                    rr.annotations().setNotes(notes);
                    api.organizer().sendToOrganizer(rr);
                }
                vulnCount[0]++;
            }
        });

        if (debugOutput) {
            outputVulCount(vulnCount[0]);
        }
    }

    public static void outputVulCount(int vulnCount) {
        api.logging().logToOutput("Repeat Strike found " + vulnCount + " potential vulnerabilit" + (vulnCount == 1 ? "y" : "ies"));
    }

    public static HttpRequestResponse makeRequest(HttpRequest request, String paramType, String paramName, String paramValue) {
        long timeoutMs = 2000;
        HttpRequest modifiedRequest = Utils.modifyRequest(request, paramType, paramName, paramValue);
        if (modifiedRequest != null) {
            return api.http().sendRequest(modifiedRequest, RequestOptions.requestOptions().withResponseTimeout(timeoutMs));
        }
        return null;
    }

    public static HttpRequestResponse makeRequestAndVerifyUsingObject(HttpRequestResponse httpReqResp, String paramType, String paramName, String paramValue, int probeNumber, Object scanCheck) {
        HttpRequestResponse requestResponse = makeRequest(httpReqResp.request(), paramType, paramName, paramValue);
        if (requestResponse != null && requestResponse.response() != null) {
            if (didProbeWork(scanCheck, requestResponse.response(), probeNumber)) {
                return requestResponse;
            }
        }
        return null;
    }
}

