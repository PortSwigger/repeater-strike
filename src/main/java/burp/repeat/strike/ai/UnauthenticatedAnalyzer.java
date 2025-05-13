package burp.repeat.strike.ai;

import burp.api.montoya.http.message.responses.HttpResponse;
import burp.repeat.strike.utils.Utils;
import org.json.JSONObject;

import java.io.PrintWriter;
import java.io.StringWriter;

import static burp.repeat.strike.RepeatStrikeExtension.api;

public class UnauthenticatedAnalyzer {
    public static JSONObject analyze(HttpResponse response) {
        try {
            AI ai = new AI();
            ai.setBypassRateLimit(true);
            ai.setSystemMessage("""
                        You are a web security expert.
                        You should analyze the response and determine if you are logged in.
                        You should look out for things that suggest you're logged in. 
                        Examples include: 
                        - a logout link or button. 
                        - Output of a username
                        - An image to suggest you have an avatar.
                        - A profile link
                        - A welcome message that mentions your name 
                        
                        Once you have determined if you are logged in you should return a string of "authenticated" or "unauthenticated".                      
                        """);
            ai.setPrompt(Utils.getResponseAsJson(response));
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
