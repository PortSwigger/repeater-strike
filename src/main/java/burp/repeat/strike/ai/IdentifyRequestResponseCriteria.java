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
                    Analyze the given HTTP request and response.
                    Determine if the target is a "DOCUMENT" (e.g., HTML, JSON) or a "RESOURCE" (e.g., images, scripts).
                    
                    Return a single JSON object (no markdown, no explanations) with the following format:
                    {
                      "type": "DOCUMENT" | "RESOURCE"
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
