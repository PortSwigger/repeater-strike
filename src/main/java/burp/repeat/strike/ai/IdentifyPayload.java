package burp.repeat.strike.ai;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.repeat.strike.RepeatStrikeExtension;
import burp.repeat.strike.settings.InvalidTypeSettingException;
import burp.repeat.strike.settings.UnregisteredSettingException;
import burp.repeat.strike.utils.Utils;
import org.json.JSONObject;

import java.io.PrintWriter;
import java.io.StringWriter;

import static burp.repeat.strike.RepeatStrikeExtension.api;

public class IdentifyPayload {
    public static JSONObject identify(HttpRequest request) {
        try {
            boolean debugAi;
            try {
                debugAi = RepeatStrikeExtension.generalSettings.getBoolean("debugAi");
            } catch (UnregisteredSettingException | InvalidTypeSettingException e) {
                api.logging().logToError("Error loading settings:" + e);
                throw new RuntimeException(e);
            }
            AI ai = new AI();
            ai.setBypassRateLimit(true);
            ai.setSystemMessage("""
                        You are a web security expert.
                        You are going to analyse a request and determine which parameter or header the user is testing. 
                        Ignore any blank parameter. Focus on parameters that look like security testing.
                        Do not output markdown.
                        Return a single JSON object with the following structure:
                        {
                          "name": string,
                          "value": string,
                          "type": "URL" | "HEADER" | "BODY" | "JSON" | "COOKIE"
                        }
                        """);
            JSONObject requestJSON = new JSONObject();
            requestJSON.put("request", Utils.truncateRequest(request));
            ai.setPrompt("Request:\n"+requestJSON);
            ai.setTemperature(1.0);
            if(debugAi) {
                api.logging().logToOutput("Sending information to the AI");
                api.logging().logToOutput(ai.getSystemMessage()+ai.getPrompt());
            }
            return new JSONObject(ai.execute());
        } catch (Throwable throwable) {
            StringWriter writer = new StringWriter();
            throwable.printStackTrace(new PrintWriter(writer));
            api.logging().logToError(writer.toString());
        }
        return null;
    }
}
