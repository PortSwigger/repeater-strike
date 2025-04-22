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
                        You are going to be given a request and response.
                        Do not output markdown. 
                        Look at the request and response and create a Burp Suite Repeater name                     
                        that's relevant to the vulnerability found. It should be short and concise. 
                        It should just contain only alphanumerics and spaces and periods. 
                        You can use the host header, the request and response when coming up with your Repeater name.                 
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
