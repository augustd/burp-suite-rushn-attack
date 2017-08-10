package burp;

import com.codemagi.burp.BaseExtender;
import com.codemagi.burp.parser.HttpResponse;
import java.io.IOException;
import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Burp Extender to enable selectively removing cache headers from proxy
 * responses.
 *
 * @author August Detlefsen [augustd at codemagi dot com]
 */
public class BurpExtender extends BaseExtender implements IHttpListener {

    public static final String EXTENSION_NAME = "Rush'n Attack";

    // pattern used to parse out the token from the PUT response
    private static final Pattern URL_PATTERN = Pattern.compile("/(Content|Scripts|fonts|bower_components)");
    private String paragraphId;

    @Override
    protected void initialize() {
        //set the extension Name
        extensionName = EXTENSION_NAME;

        //tell Burp we want to process HTTP requests                                                                                                                                                     
        callbacks.registerHttpListener(this);
    }

    /**
     * There are three parts to a sandbox query:
     * <ol>
     * <li>The initial PUT request that creates the query ID
     * <li>The POST request that submits the query
     * <li>The GET request that returns the results
     * </ol>
     *
     * SQLMap will send the POST request. We need to:
     * <ol>
     * <li>Synthesize the PUT request and parse the query ID from the response
     * <li>Submit the POST request with the correct query ID
     * <li>Modify the POST response so that it redirects SQLMap to the correct
     * results
     * <ol>
     *
     * @param toolFlag
     * @param messageIsRequest
     * @param messageInfo
     */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {

        //we want to work on proxy only
        if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) {
            if (!messageIsRequest) {
                //handle the POST request received from SQLmap

                //first check the URL to see if this is a request we want to filter
                IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
                URL requestUrl = requestInfo.getUrl();
                String urlPath = requestUrl.getPath();
                Matcher matcher = URL_PATTERN.matcher(urlPath);
                if (matcher.find()) {

                    try {
                        //parse the response
                        HttpResponse response = HttpResponse.parseMessage(messageInfo.getResponse());

                        //remove the cache headers
                        response.removeHeader("Pragma");
                        response.removeHeader("Cache-Control");
                        response.removeHeader("Expires");

                        //return the modified response
                        messageInfo.setResponse(response.getBytes());
                        
                    } catch (IOException ex) {
                        printStackTrace(ex);
                    }
                }
            }
        }
    }

}
