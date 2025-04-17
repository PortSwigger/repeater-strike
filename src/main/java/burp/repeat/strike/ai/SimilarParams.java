package burp.repeat.strike.ai;

import burp.repeat.strike.RepeatStrikeExtension;
import burp.repeat.strike.settings.InvalidTypeSettingException;
import burp.repeat.strike.settings.UnregisteredSettingException;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;

import static burp.repeat.strike.RepeatStrikeExtension.api;

public class SimilarParams {
    public static void getSimilarParams(String paramName, ArrayList<String> params) {
        RepeatStrikeExtension.executorService.submit(() -> {
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
                        
                        """);

                ai.setPrompt("");
                ai.setTemperature(1.0);
                if(debugAi) {
                    api.logging().logToOutput("Sending information to the AI");
                }
                String response = ai.execute();
                try {
                    String[] vectors = response.split("\n");
                    JSONArray variations = new JSONArray();
                    for (String vector : vectors) {
                        JSONObject variation = new JSONObject();
                        variation.put("vector", vector.trim());
                        variations.put(variation);
                    }
                    if(debugAi) {
                        api.logging().logToOutput("Variations found:\n" + variations);
                    }
                } catch (JSONException e) {
                    api.logging().logToError("The AI returned invalid JSON");
                }
            } catch (Throwable throwable) {
                StringWriter writer = new StringWriter();
                throwable.printStackTrace(new PrintWriter(writer));
                api.logging().logToError(writer.toString());
            }
        });
    }
}
