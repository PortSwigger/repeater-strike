package burp.repeat.strike.diffing;

import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.AttributeType;

import java.util.ArrayList;
import java.util.Set;

public class DiffingAttributes {
    public Set<AttributeType> variantAttributes;
    public Set<AttributeType> invariantAttributes;
    public ArrayList<HttpResponse> controlResponses = new ArrayList<>();

    public DiffingAttributes(Set<AttributeType> variantAttributes, Set<AttributeType> invariantAttributes, ArrayList<HttpResponse> controlResponses) {
        this.variantAttributes = variantAttributes;
        this.invariantAttributes = invariantAttributes;
        this.controlResponses = controlResponses;
    }
}
