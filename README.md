![Repeater Strike logo](https://github.com/hackvertor/repeat-strike/blob/main/src/main/resources/images/logo.png)

# Repeater Strike

Repeater Strike is an AI-powered tool that helps uncover IDOR and other vulnerabilities by analyzing your Repeater requests. It automatically generates targeted regular expressions based on the requests and responses you're testing. Once a vulnerability is detected, these regexes are applied to your proxy history to rapidly identify similar issues across your entire traffic, helping you scale your findings and save time.

![Repeater Strike Demo](https://github.com/hackvertor/repeat-strike/blob/main/videos/repeater-strike-demo.gif)

## Installation instructions

**In Burp Suite Professional, go to Extensions->BApp store and search for Repeater Strike. Click the installation button and then navigate to the installed tab then select Repeater Strike and check the "Use AI" checkbox in the Extension tab.**

![Installation screen](https://github.com/hackvertor/repeat-strike/blob/main/screenshots/repeater-strike-screenshot.png)

## How to use

In Repeater identify the target you want to test. You can use this Academy Lab as a test case:
[Academy Lab](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter)

1. Open the Academy lab in Burp's browser and log in using the provided credentials.
2. Note the API key and send the request to Repeater via the proxy.
3. In Repeater, make a request to the host, then right-click → Extensions → Repeater Strike → Send to Repeater Strike.
4. In the Repeater Strike tab, open the Word list sub-tab and click Populate with default word list.
5. Switch to the Requests/Responses queue sub-tab and click Generate Strike Rule.
6. Choose Using AI Regex; if successful, save the Strike Rule, and it will scan the proxy history.

Edit saved Strike Rules in the "Saved Strike Rules" tab and scan proxy history anytime using the "Run Strike rule on proxy history" button.

## Settings

Configure Repeater Strike in Extension tab → Extensions settings → Repeater Strike.
Here, you can set proxy data scan limits, request/response/image caps, and enable automatic Strike Rules and proxy history scanning when sending Repeater requests.