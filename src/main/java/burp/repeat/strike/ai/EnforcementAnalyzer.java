package burp.repeat.strike.ai;

import burp.api.montoya.http.message.responses.HttpResponse;
import burp.repeat.strike.utils.Utils;

import java.io.PrintWriter;
import java.io.StringWriter;

import static burp.repeat.strike.RepeatStrikeExtension.api;

public class EnforcementAnalyzer {
    public static String analyze(HttpResponse response) {
        try {
            AI ai = new AI();
            ai.setBypassRateLimit(true);
            ai.setSystemMessage("""
                        You are a web security expert.
                        You are going to be given a response and your job is to see if you have been denied access to the resource.
                        You should look at the response and look for messages to suggest you don't have access.
                        If you think you've been blocked from accessing something you shouldn't return the string "blocked", if you haven't been blocked in any way then return the string "allowed".
                        """);
            ai.setPrompt(Utils.getResponseAsJson(response));
            ai.setTemperature(1.0);
            return ai.execute().trim();
        } catch (Throwable throwable) {
            StringWriter writer = new StringWriter();
            throwable.printStackTrace(new PrintWriter(writer));
            api.logging().logToError(writer.toString());
        }
        return null;
    }
}
