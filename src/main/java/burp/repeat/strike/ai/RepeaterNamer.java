package burp.repeat.strike.ai;

import burp.repeat.strike.RepeatStrikeExtension;
import burp.repeat.strike.settings.InvalidTypeSettingException;
import burp.repeat.strike.settings.UnregisteredSettingException;

import java.io.PrintWriter;
import java.io.StringWriter;

import static burp.repeat.strike.RepeatStrikeExtension.api;

public class RepeaterNamer {
    public static String generateName(String request, String response) {
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
                    You will be provided with an HTTP request and response.
                    Analyze them to identify any potential vulnerabilities.
                    Generate a short, relevant Burp Suite Repeater tab name that summarizes the issue.
                    Your output must:
                    - Be concise and informative
                    - Contain only alphanumerics, spaces, and optional periods
                    - Avoid markdown or formatting
                    - Leverage context from the Host header, request, and response
                    Output only the Repeater tab name. Nothing else.
                    """);

            ai.setPrompt("Request:\n"+request+"\n\nResponse:\n"+response);
            ai.setTemperature(1.0);
            if(debugAi) {
                api.logging().logToOutput("Sending information to the AI");
                api.logging().logToOutput(ai.getSystemMessage()+ai.getPrompt());
            }
            String aiResponse = ai.execute();
            if(debugAi) {
                api.logging().logToOutput("AI response:\n"+aiResponse);
            }
            return aiResponse.replaceAll("_"," ");
        } catch (Throwable throwable) {
            StringWriter writer = new StringWriter();
            throwable.printStackTrace(new PrintWriter(writer));
            api.logging().logToError(writer.toString());
        }
        return "";
    }
}
