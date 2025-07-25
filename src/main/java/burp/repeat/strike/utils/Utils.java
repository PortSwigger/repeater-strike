package burp.repeat.strike.utils;


import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import burp.api.montoya.http.message.responses.analysis.ResponseVariationsAnalyzer;
import burp.repeat.strike.RepeatStrikeExtension;
import org.json.JSONArray;
import org.json.JSONObject;

import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;

import static burp.repeat.strike.RepeatStrikeExtension.*;
import static burp.repeat.strike.diffing.RequestDiffer.filterHeaders;
import static burp.repeat.strike.proxy.AnalyseProxyHistory.makeRequest;

public class Utils {

    public static boolean isUrlEncoded(String value) {
        return Pattern.compile("%[a-fA-F0-9]{2}").matcher(value).find();
    }

    public static String getParameterValue(HttpRequest request, String name, String type) {
        type = type.toUpperCase();
        return switch (type) {
            case "HEADER" -> request.headerValue(name);
            case "PATH" -> request.pathWithoutQuery();
            case "URL", "BODY", "COOKIE", "JSON" -> request.parameter(name, HttpParameterType.valueOf(type.toUpperCase())).value();
            default -> null;
        };
    }

    public static boolean hasDigits(String input) {
        return input.matches(".*\\d.*");
    }

    public static String replaceDigits(String base, String replacementDigits) {
        StringBuilder result = new StringBuilder();
        int digitIndex = 0;

        for (int i = 0; i < base.length(); i++) {
            char c = base.charAt(i);
            if (Character.isDigit(c)) {
                if (digitIndex < replacementDigits.length()) {
                    result.append(replacementDigits.charAt(digitIndex++));
                } else {
                    result.append(c);
                }
            } else {
                result.append(c);
            }
        }

        return result.toString();
    }


    public static String replaceNumericValuesInPath(String basePath, String attackPath) {
        if(hasDigits(basePath) && hasDigits(attackPath)) {
            return replaceDigits(basePath, attackPath);
        }
        return basePath;
    }

    public static HttpRequest modifyRequest(HttpRequest req, String type, String name, String value) {
        type = type.toUpperCase();
        return switch (type) {
            case "HEADER" -> req.withRemovedHeader(name).withAddedHeader(name, value);
            case "PATH" -> req.withPath(value.startsWith("/") ? value : "/" + value);
            case "URL", "BODY", "COOKIE", "JSON" -> {
                if ((type.equals("BODY") || type.equals("URL")) && !isUrlEncoded(value)) {
                    value = api.utilities().urlUtils().encode(value);
                }
                yield req.withUpdatedParameters(HttpParameter.parameter(name, value, HttpParameterType.valueOf(type)));
            }
            default -> req;
        };
    }

    public static void openUrl(String url) {
        if(url.startsWith("https://")) {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                try {
                    Desktop.getDesktop().browse(new URI(url));
                } catch (IOException | URISyntaxException ignored) {
                }
            }
        }
    }

    public static ImageIcon createImageIcon(String path, String description) {
        java.net.URL imgURL = RepeatStrikeExtension.class.getResource(path);
        if (imgURL != null) {
            return new ImageIcon(imgURL, description);
        } else {
            api.logging().logToError("Couldn't find file: " + path);
            return null;
        }
    }

    public static boolean checkIfCanSetNotes(Annotations annotations) {
        try {
            String notes = annotations.notes();
            annotations.setNotes(notes);
            return true;
        } catch(UnsupportedOperationException ignored) {
            return false;
        }
    }

    public static String generateRequestKey(HttpRequest req) {
        String currentHost = req.httpService().host();
        String headerNames = req.headers().stream().map(HttpHeader::name).collect(Collectors.joining(","));
        String paramNames = req.parameters().stream().map(ParsedHttpParameter::name).collect(Collectors.joining(","));
        return currentHost + "|" + paramNames + "|" + headerNames;
    }

    public static void resetHistory(boolean shouldDebug) {
        requestHistory = new ArrayList<>();
        responseHistory = new ArrayList<>();
        if(shouldDebug) {
            api.logging().logToOutput("Request history reset");
        }
        repeatStrikeTab.clearQueue();
    }

    public static String escapeInvalidRegexMeta(String input) {
        StringBuilder result = new StringBuilder();
        boolean inCharClass = false;
        boolean escaped = false;

        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);

            if (escaped) {
                result.append(c);
                escaped = false;
                continue;
            }

            if (c == '\\') {
                result.append(c);
                escaped = true;
                continue;
            }

            if (c == '[') {
                inCharClass = true;
                result.append(c);
                continue;
            }

            if (c == ']') {
                inCharClass = false;
                result.append(c);
                continue;
            }

            if (!inCharClass && (c == '{')) {
                int j = i + 1;
                boolean validQuantifier = false;
                while (j < input.length() && Character.isDigit(input.charAt(j))) j++;
                if (j < input.length() && input.charAt(j) == '}') {
                    validQuantifier = true;
                } else if (j < input.length() && input.charAt(j) == ',') {
                    j++;
                    while (j < input.length() && Character.isDigit(input.charAt(j))) j++;
                    if (j < input.length() && input.charAt(j) == '}') {
                        validQuantifier = true;
                    }
                }

                if (!validQuantifier) {
                    result.append('\\');
                }
                result.append(c);
                continue;
            }

            if (!inCharClass && c == '}') {
                boolean valid = false;
                int k = i - 1;
                while (k >= 0 && Character.isDigit(input.charAt(k))) k--;
                if (k >= 0 && input.charAt(k) == '{') {
                    valid = true;
                } else if (k >= 0 && input.charAt(k) == ',') {
                    k--;
                    while (k >= 0 && Character.isDigit(input.charAt(k))) k--;
                    if (k >= 0 && input.charAt(k) == '{') {
                        valid = true;
                    }
                }

                if (!valid) {
                    result.append('\\');
                }
                result.append(c);
                continue;
            }

            result.append(c);
        }

        return result.toString();
    }

    public static Pattern generatePattern(String regex) {
        try {
            return Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        } catch(PatternSyntaxException e) {
            return Pattern.compile(escapeInvalidRegexMeta(regex), Pattern.CASE_INSENSITIVE);
        }
    }

    public static String truncateRequest(HttpRequest request) {
        int maxRequestLimit = settings.getInteger("Max request limit");
        String output = request.toString();
        if(output.length() > maxRequestLimit) {
            output = output.substring(0, maxRequestLimit);
        }
        return output;
    }
    public static String truncateResponse(HttpResponse response) {
        int maxImageResponseLimit = settings.getInteger("Max image response limit");
        int maxResponseLimit = settings.getInteger("Max response limit");
        String output = response.toString();
        if(response.mimeType().toString().toLowerCase().startsWith("image") && output.length() > maxImageResponseLimit) {
            output = output.substring(0, maxImageResponseLimit);
        }
        if(output.length() > maxResponseLimit) {
            output = output.substring(0, maxResponseLimit);
        }
        return output;
    }

    public static JSONArray getResponsesAsJson(HttpResponse[] responses) {
        JSONArray responsesJSON = new JSONArray();
        for(HttpResponse response : responses) {
            JSONObject json = new JSONObject();
            json.put("response", Utils.truncateResponse(response));
            responsesJSON.put(json);
        }
        return responsesJSON;
    }

    public static JSONArray getRequestsAsJson(HttpRequest[] requests) {
        JSONArray requestsJSON = new JSONArray();
        HttpRequest[] requestsWithoutFilteredHeaders = filterHeaders(requests);
        for(HttpRequest request : requestsWithoutFilteredHeaders) {
            JSONObject json = new JSONObject();
            json.put("request", Utils.truncateRequest(request));
            requestsJSON.put(json);
        }
        return requestsJSON;
    }

    public static String getRequestsAndResponsesPrompt(HttpRequest[] requests, HttpResponse[] responses) {
        JSONArray requestsJSON = getRequestsAsJson(requests);
        JSONArray responsesJSON = getResponsesAsJson(responses);
        return "Requests:\n"+requestsJSON+"\n\nResponses:\n"+responsesJSON;
    }

    public static void alert(String message) {
        JOptionPane.showMessageDialog(null, message);
    }

    public static boolean confirm(JComponent component, String title, String message) {
        return JOptionPane.showConfirmDialog(component, message, title, JOptionPane.YES_NO_OPTION) == 0;
    }

    public static String prompt(JComponent component, String title, String message) {
        return JOptionPane.showInputDialog(component, message, title, JOptionPane.QUESTION_MESSAGE);
    }

    public static String getInvariantFingerprint(ResponseVariationsAnalyzer analyzer) {
        return analyzer.invariantAttributes().stream().map(AttributeType::name).collect(Collectors.joining(","));
    }

    public static String getVariantFingerprint(ResponseVariationsAnalyzer analyzer) {
        return analyzer.variantAttributes().stream().map(AttributeType::name).collect(Collectors.joining(","));
    }

    public static ArrayList<HttpRequestResponse> getBaseResponses(HttpRequest request, String paramType, String paramName) {
        ArrayList<HttpRequestResponse> baseResponses = new ArrayList<>();
        for(int i=0;i<2;i++) {
            HttpRequestResponse baseRequestResponse = null;
            baseRequestResponse = makeRequest(request, paramType, paramName, Utils.randomAlphaString(1) + Utils.randomString(7));
            if(baseRequestResponse == null) {
                return null;
            }
            baseResponses.add(baseRequestResponse);
        }
        return baseResponses;
    }

    public static boolean checkForDifferences(HttpRequest request, String baseFingerprint, ArrayList<HttpRequestResponse> baseResponses, String paramType, String paramName, String paramValue, boolean sendToOrganizer) {
        HttpRequestResponse attackRequestResponse = makeRequest(request, paramType, paramName, paramValue);
        if (attackRequestResponse != null) {
            String fingerprint = Utils.getFingerprint(baseResponses, attackRequestResponse.response());
            if(!fingerprint.equals(baseFingerprint)) {
                if(sendToOrganizer) {
                    attackRequestResponse.annotations().setNotes("Attack found using diffing");
                    api.organizer().sendToOrganizer(attackRequestResponse);
                }
                return true;
            }
        }
        return false;
    }

    public static String getBaseFingerprint(ArrayList<HttpRequestResponse> baseResponses) {
        ResponseVariationsAnalyzer analyzer = api.http().createResponseVariationsAnalyzer();
        for(HttpRequestResponse baseResponse: baseResponses) {
            analyzer.updateWith(baseResponse.response());
        }
        return Utils.getInvariantFingerprint(analyzer);
    }

    public static String getFingerprint(ArrayList<HttpRequestResponse> baseResponses, HttpResponse response) {
        ResponseVariationsAnalyzer analyzer = api.http().createResponseVariationsAnalyzer();
        for(HttpRequestResponse baseResponse: baseResponses) {
            analyzer.updateWith(baseResponse.response());
        }
        analyzer.updateWith(response);
        return Utils.getInvariantFingerprint(analyzer);
    }

    public static String randomAlphaString(int length) {
        String CHARACTERS = "abcdefghijklmnopqrstuvwxyz";
        SecureRandom RANDOM = new SecureRandom();
        if (length <= 0) {
            throw new IllegalArgumentException("Length must be greater than 0");
        }
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(CHARACTERS.charAt(RANDOM.nextInt(CHARACTERS.length())));
        }

        return sb.toString();
    }

    public static String randomString(int length) throws IllegalArgumentException {
        String CHARACTERS = "abcdefghijklmnopqrstuvwxyz0123456789";
        SecureRandom RANDOM = new SecureRandom();
        if (length <= 0) {
            throw new IllegalArgumentException("Length must be greater than 0");
        }
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(CHARACTERS.charAt(RANDOM.nextInt(CHARACTERS.length())));
        }

        return sb.toString();
    }
}
