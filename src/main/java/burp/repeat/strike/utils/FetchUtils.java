package burp.repeat.strike.utils;

import burp.api.montoya.http.message.requests.HttpRequest;

public class FetchUtils {
    private static boolean checkFetchHeader(HttpRequest request, String value) {
        return request.hasHeader("Sec-Fetch-Dest") && request.headerValue("Sec-Fetch-Dest").trim().equalsIgnoreCase(value);
    }

    public static boolean isDocument(HttpRequest request) {
        return checkFetchHeader(request, "document");
    }

    public static boolean isEmbed(HttpRequest request) {
        return checkFetchHeader(request, "embed");
    }

    public static boolean IsEmpty(HttpRequest request) {
        return checkFetchHeader(request, "empty");
    }

    public static boolean isFont(HttpRequest request) {
        return checkFetchHeader(request, "font");
    }

    public static boolean isFrame(HttpRequest request) {
        return checkFetchHeader(request, "frame");
    }

    public static boolean isIframe(HttpRequest request) {
        return checkFetchHeader(request, "iframe");
    }

    public static boolean isImage(HttpRequest request) {
        return checkFetchHeader(request, "image");
    }

    public static boolean isManifest(HttpRequest request) {
        return checkFetchHeader(request, "manifest");
    }

    public static boolean isObject(HttpRequest request) {
        return checkFetchHeader(request, "object");
    }

    public static boolean isReport(HttpRequest request) {
        return checkFetchHeader(request, "report");
    }

    public static boolean isScript(HttpRequest request) {
        return checkFetchHeader(request, "script");
    }

    public static boolean isServiceworker(HttpRequest request) {
        return checkFetchHeader(request, "serviceworker");
    }

    public static boolean isSharedworker(HttpRequest request) {
        return checkFetchHeader(request, "sharedworker");
    }

    public static boolean isStyle(HttpRequest request) {
        return checkFetchHeader(request, "style");
    }

    public static boolean isTrack(HttpRequest request) {
        return checkFetchHeader(request, "track");
    }

    public static boolean isVideo(HttpRequest request) {
        return checkFetchHeader(request, "video");
    }

    public static boolean isWorker(HttpRequest request) {
        return checkFetchHeader(request, "worker");
    }

    public static boolean isXslt(HttpRequest request) {
        return checkFetchHeader(request, "xslt");
    }
}
