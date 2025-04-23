package burp.repeat.strike.ai;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.repeat.strike.utils.Utils;
import org.json.JSONObject;

import java.io.PrintWriter;
import java.io.StringWriter;

import static burp.repeat.strike.RepeatStrikeExtension.api;

public class IdentifyRequestResponseCriteria {
    public static JSONObject identify(HttpRequest request, HttpResponse response) {
        try {
            AI ai = new AI();
            ai.setBypassRateLimit(true);
            ai.setSystemMessage("""
                        You are a web security expert.
                        You first should identify what is being tested.
                        Your job is to analyse HTTP requests/responses and build criteria to identify similar requests.
                        You should analyse the request and response to determine if it is a resource or a document.
                        You should generate a regular expression to find vulnerability of the type detected on the response.
                        You should generate a regular expression to identify similar parameter names.
                        Do not output markdown.
                        Return a single JSON object with the following structure:
                        {
                          "type": "DOCUMENT" | "RESOURCE",
                          "responseRegex": RegExp String,
                          "parameterRegex": RegExp String
                        }
                        """);
            JSONObject requestJSON = new JSONObject();
            requestJSON.put("request", Utils.truncateRequest(request));
            JSONObject responseJSON = new JSONObject();
            responseJSON.put("response", Utils.truncateResponse(response));
            ai.setPrompt("Request:\n"+requestJSON+"\n\nResponse:\n"+responseJSON);
            ai.setTemperature(1.0);
            String aiResponse = ai.execute();
            return new JSONObject(aiResponse);
        } catch (Throwable throwable) {
            StringWriter writer = new StringWriter();
            throwable.printStackTrace(new PrintWriter(writer));
            api.logging().logToError(writer.toString());
        }
        return null;
    }
}
