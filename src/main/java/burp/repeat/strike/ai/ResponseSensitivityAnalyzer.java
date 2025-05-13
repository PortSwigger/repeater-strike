package burp.repeat.strike.ai;

import burp.api.montoya.http.message.responses.HttpResponse;
import burp.repeat.strike.utils.Utils;

import java.io.PrintWriter;
import java.io.StringWriter;

import static burp.repeat.strike.RepeatStrikeExtension.api;

public class ResponseSensitivityAnalyzer {
    public static String analyze(HttpResponse response) {
        try {
            AI ai = new AI();
            ai.setBypassRateLimit(true);
            ai.setSystemMessage("""
                        You are a web security expert.
                        Your job is to look at response and decide if there is anything sensitive.
                        Once you've found some sensitive data you should return it as a string.
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
