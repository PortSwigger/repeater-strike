package burp.repeat.strike.ai;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.repeat.strike.utils.Utils;
import org.json.JSONObject;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Arrays;

import static burp.repeat.strike.RepeatStrikeExtension.api;
import static burp.repeat.strike.RepeatStrikeExtension.repeatStrikePanel;

public class IdentifyPayload {
    public static JSONObject identify(HttpRequest[] requests, HttpResponse[] responses) {
        try {
            repeatStrikePanel.setStatus("Identifying vulnerability", false);
            AI ai = new AI();
            ai.setBypassRateLimit(true);
            ai.setSystemMessage("""
                        You are a web security expert.
                        You are going to analyse requests and responses and determine which parameter or header the user is testing. 
                        Ignore any blank parameter. Focus on parameters that look like security testing.
                        Once you have identified the parameter you should look at what vulnerability class they are looking for and update the vulnerability class property.
                        Do not output markdown.
                        Return a single JSON object with the following structure:
                        {
                          "name": string,
                          "values": [string],
                          "type": "URL" | "PATH" | "HEADER" | "BODY" | "JSON" | "COOKIE",
                          "vulnerabilityClass": """+" \""+String.join("\" | \"", Arrays.stream(Vulnerability.values()).map(Enum::name).toArray(String[]::new))+"\"\n"+"""                
                        }
                        """);
            ai.setPrompt(Utils.getRequestsAndResponsesAsJson(requests, responses));
            ai.setTemperature(1.0);
            return new JSONObject(ai.execute());
        } catch (Throwable throwable) {
            StringWriter writer = new StringWriter();
            throwable.printStackTrace(new PrintWriter(writer));
            api.logging().logToError(writer.toString());
        }
        return null;
    }
}
