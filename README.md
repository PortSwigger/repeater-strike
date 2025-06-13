![Repeat Strike logo](https://github.com/hackvertor/repeat-strike/blob/main/src/main/resources/images/logo.png)

# Repeat Strike

Repeat Strike is an AI-powered tool that helps uncover IDOR and other vulnerabilities by analyzing your Repeater requests. It automatically generates targeted regular expressions based on the requests and responses you're testing. Once a vulnerability is detected, these regexes are applied to your proxy history to rapidly identify similar issues across your entire traffic, helping you scale your findings and save time.

![Repeat Strike Demo](https://github.com/hackvertor/repeat-strike/blob/main/videos/repeat-strike-demo.gif)

## Installation instructions

**In Burp Suite Professional, go to Extensions->BApp store and search for Repeat Strike. Click the install button and then navigate to the installed tab then select Repeat Strike and check the "Use AI" checkbox in the Extension tab.**

![Installation screen](https://github.com/hackvertor/repeat-strike/blob/main/screenshots/repeat-strike-install-screenshot.png)

## How to use

In Repeater identify the target you want to test. You can use this Academy Lab as a test case:
[Academy Lab](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter)

1. Open the Academy lab in Burp's browser and log in using the provided credentials.
2. Note the API key and send the request to Repeater via the proxy.
3. In Repeater, make a request to the host, then right-click → Extensions → Repeat Strike → Send to Repeat Strike.
4. In the Repeat Strike tab, open the Word list sub-tab and click Populate with default word list.
5. Switch to the Requests/Responses queue sub-tab and click Generate scan check.
6. Choose Using AI Regex; if successful, save the scan check and it will scan the proxy history.

Edit saved scan checks in the "Saved scan checks" tab and scan proxy history anytime using the "Scan proxy history" button.

## Settings

Configure Repeat Strike in Repeat Strike → Settings.
Here, you can set proxy data scan limits, request/response/image caps, and enable automatic scan checks and proxy history scanning when sending Repeater requests.