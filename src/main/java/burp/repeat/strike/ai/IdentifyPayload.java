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
                        Do not output markdown. When using the path always include the full path prefix in the value.                        
                        *important* Note name is not relevant for path types.  
                        URL types should be use for get parameters. When generating a URL type the value should be the value of the parameter and the name should go in the name property.                   
                        Return a single JSON object with the following structure:
                        {
                          "name": string,                         
                          "values": [string],
                          "type": "URL" | "PATH" | "HEADER" | "BODY" | "JSON" | "COOKIE",
                          "vulnerabilityClass": """+" \""+String.join("\" | \"", Arrays.stream(Vulnerability.values()).map(Enum::name).toArray(String[]::new))+"\"\n"+"""                
                        }
                        """);
            ai.setPrompt(Utils.getRequestsAndResponsesPrompt(requests, responses));
            ai.setTemperature(1.0);
            JSONObject json = new JSONObject(ai.execute());
            if(json.get("name") == null) {
                json.put("name", "");
            }
            return json;
        } catch (Throwable throwable) {
            StringWriter writer = new StringWriter();
            throwable.printStackTrace(new PrintWriter(writer));
            api.logging().logToError(writer.toString());
        }
        return null;
    }
}
