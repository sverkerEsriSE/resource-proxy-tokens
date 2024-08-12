<%@ WebHandler Language="C#" Class="proxy" %>
/*
 * Mofified DotNet proxy client.
 *
 * Version 1.1.1-beta
 * See https://github.com/Esri/resource-proxy for more information.
 * or https://github.com/sverkerEsriSE/resource-proxy-tokens
 *
 */

#define TRACE
using System;
using System.IO;
using System.Web;
using System.Xml.Serialization;
using System.Web.Caching;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Net;

public class proxy : IHttpHandler {

    private static String version = "1.1.1-beta";

    private static String proxy_url = "";
    private bool wmsResourceRewrite = false;
	private bool changeEncodingToUTF8 = false;
    private bool flipWmsBboxCoords = false;
	private bool isWMTS = false;
    private string requestKey = "";

    class RateMeter {
        double _rate; //internal rate is stored in requests per second
        int _countCap;
        double _count = 0;
        DateTime _lastUpdate = DateTime.Now;

        public RateMeter(int rate_limit, int rate_limit_period) {
            _rate = (double) rate_limit / rate_limit_period / 60;
            _countCap = rate_limit;
        }

        //called when rate-limited endpoint is invoked
        public bool click() {
            TimeSpan ts = DateTime.Now - _lastUpdate;
            _lastUpdate = DateTime.Now;
            //assuming uniform distribution of requests over time,
            //reducing the counter according to # of seconds passed
            //since last invocation
            _count = Math.Max(0, _count - ts.TotalSeconds * _rate);
            if (_count <= _countCap) {
                //good to proceed
                _count++;
                return true;
            }
            return false;
        }

        public bool canBeCleaned() {
            TimeSpan ts = DateTime.Now - _lastUpdate;
            return _count - ts.TotalSeconds * _rate <= 0;
        }
    }

    private static string PROXY_REFERER = "http://localhost/proxy/proxy.ashx";
    private static string DEFAULT_OAUTH = "https://www.arcgis.com/sharing/oauth2/";
    private static int CLEAN_RATEMAP_AFTER = 10000; //clean the rateMap every xxxx requests
    private static System.Net.IWebProxy SYSTEM_PROXY = System.Net.HttpWebRequest.DefaultWebProxy; // Use the default system proxy
    private static LogTraceListener logTraceListener = null;
    private static Object _rateMapLock = new Object();

    public void ProcessRequest(HttpContext context) {

	if (context.Request.Url.IsDefaultPort) {
        	proxy_url = context.Request.Url.Scheme + "://" + context.Request.Url.Host + "/" + (context.Request.RawUrl.Split('/'))[1] + "/";
	}
	else {
		proxy_url = context.Request.Url.Scheme + "://" + context.Request.Url.Host + ":" + context.Request.Url.Port.ToString() + "/" + (context.Request.RawUrl.Split('/'))[1] + "/";
	}

        if (logTraceListener == null)
        {
            logTraceListener = new LogTraceListener();
            Trace.Listeners.Add(logTraceListener);
        }

	log(TraceLevel.Info,"Request from " + context.Request.UserHostAddress);

        HttpResponse response = context.Response;
        if (context.Request.Url.Query.Length < 1)
        {
            string errorMsg = "This proxy does not support empty parameters.";
            log(TraceLevel.Error, errorMsg);
            sendErrorResponse(context.Response, null, errorMsg, System.Net.HttpStatusCode.BadRequest);
            return;
        }
        string url = "";
        string queryString = "";
        string restFunction = "";
        if (!context.Request.Url.Query.Substring(1).Contains("url="))
        {
            url = context.Request.Url.Query.Substring(1);
            log(TraceLevel.Verbose, "URI requested by url: " + url);
        }
        else {
            var fullQuery = context.Request.Url.Query.Substring(1).Split(new char[] {'&'}, 2);

            url = fullQuery[0].Split('=')[1];

            //restFunction = fullQuery[0].Split('=')[1];
            log(TraceLevel.Verbose, "Unmodified QueryString: " + context.Request.Url.Query);
            log(TraceLevel.Verbose, "URI requested by key: " + url);
            requestKey = url;
            queryString = "";
            try {
                if (fullQuery[1].StartsWith("restFunction")) {
                    restFunction = fullQuery[1].Split(new char[] {'&'}, 2)[0].Replace("restFunction=","");
                    queryString = fullQuery[1].Split(new char[] {'&'}, 2)[1];
                }
                log(TraceLevel.Verbose, "Querystring (using by key): " + queryString);
            } catch (Exception ex)
            {
                log(TraceLevel.Verbose, "No query string supplied");
            }
        }
        //if uri is ping
        if (url.Equals("ping", StringComparison.InvariantCultureIgnoreCase))
        {
            ProxyConfig proxyConfig = ProxyConfig.GetCurrentConfig();

            String checkConfig = (proxyConfig == null) ? "Not Readable" : "OK";
            String checkLog = "";
            if (checkConfig != "OK")
            {
                checkLog = "Can not verify";
            }
            else
            {
                String filename = proxyConfig.logFile;
                checkLog = (filename != null && filename != "") ? "OK" : "Not Exist/Readable";

                if (checkLog == "OK") {
                    log(TraceLevel.Info, "Pinged");
                }
            }

            sendPingResponse(response, version, checkConfig, checkLog);
            return;
        }

        //if url is encoded, decode it.
        if (url.StartsWith("http%3a%2f%2f", StringComparison.InvariantCultureIgnoreCase) || url.StartsWith("https%3a%2f%2f", StringComparison.InvariantCultureIgnoreCase))
            url = HttpUtility.UrlDecode(url);
        
        ServerUrl serverUrl;
        try {
            serverUrl = getConfig().GetConfigServerUrl(url);

            if (serverUrl == null) {
                //if no serverUrl found, send error message and get out.
                string errorMsg = "The request URL does not match with the ServerUrl in proxy.config! Please check the proxy.config!";
                log(TraceLevel.Error, errorMsg);
                sendErrorResponse(context.Response, null, errorMsg, System.Net.HttpStatusCode.BadRequest);
                return;
            }
        }
        //if XML couldn't be parsed
        catch (InvalidOperationException ex) {

            string errorMsg = ex.InnerException.Message + " " + url;
            log(TraceLevel.Error, errorMsg);
            sendErrorResponse(context.Response, null, errorMsg, System.Net.HttpStatusCode.InternalServerError);
            return;
        }
        //if mustMatch was set to true and URL wasn't in the list
        catch (ArgumentException ex) {
            string errorMsg = ex.Message + " " + url;
            log(TraceLevel.Error, errorMsg);
            sendErrorResponse(context.Response, null, errorMsg, System.Net.HttpStatusCode.Forbidden);
            return;
        }
        
        // forceHttp check - converts https to http in the URL
        if (url.StartsWith("https") && serverUrl.ForceHttp)
        {
            url = url.Replace("https","http");
        }
        
        // set wmsResponseRewrite variable
        this.wmsResourceRewrite = (serverUrl.WMSResourceRewrite) ? true : false;
		
		// set changeEncodingToUTF8 variable
        this.changeEncodingToUTF8 = (serverUrl.ChangeEncodingToUTF8) ? true : false;

        // set flipWMSBboxCoords variable
        this.flipWmsBboxCoords = (serverUrl.FlipWMSBboxCoords) ? true : false;
		
		// set isWMTS variable
        this.isWMTS = (serverUrl.IsWMTS) ? true : false;
        
        //use actual request header instead of a placeholder, if present
        if (context.Request.Headers["referer"] != null)
            PROXY_REFERER = context.Request.Headers["referer"];

        //referer
        //check against the list of referers if they have been specified in the proxy.config
        String[] allowedReferersArray = ProxyConfig.GetAllowedReferersArray();
        if (allowedReferersArray != null && allowedReferersArray.Length > 0 && context.Request.Headers["referer"] != null)
        {
            PROXY_REFERER = context.Request.Headers["referer"];
            string requestReferer = context.Request.Headers["referer"];
            try
            {
                String checkValidUri = new UriBuilder(requestReferer.StartsWith("//") ? requestReferer.Substring(requestReferer.IndexOf("//") + 2) : requestReferer).Host;

            }
            catch (Exception e)
            {
                log(TraceLevel.Warning, "Proxy is being used from an invalid referer: " + context.Request.Headers["referer"]);
                sendErrorResponse(context.Response, "Error verifying referer. ", "403 - Forbidden: Access is denied.", System.Net.HttpStatusCode.Forbidden);
                return;
            }

            if (!checkReferer(allowedReferersArray, requestReferer))
            {
                log(TraceLevel.Warning, "Proxy is being used from an unknown referer: " + context.Request.Headers["referer"]);
                sendErrorResponse(context.Response, "Unsupported referer. ", "403 - Forbidden: Access is denied.", System.Net.HttpStatusCode.Forbidden);
            }


        }

        //Check to see if allowed referer list is specified and reject if referer is null
        if (context.Request.Headers["referer"] == null && allowedReferersArray != null && !allowedReferersArray[0].Equals("*"))
        {
            log(TraceLevel.Warning, "Proxy is being called by a null referer.  Access denied.");
            sendErrorResponse(response, "Current proxy configuration settings do not allow requests which do not include a referer header.", "403 - Forbidden: Access is denied.", System.Net.HttpStatusCode.Forbidden);
            return;
        }

        //Throttling: checking the rate limit coming from particular client IP
        if (serverUrl.RateLimit > -1) {
            lock (_rateMapLock)
            {
                ConcurrentDictionary<string, RateMeter> ratemap = (ConcurrentDictionary<string, RateMeter>)context.Application["rateMap"];
                if (ratemap == null)
                {
                    ratemap = new ConcurrentDictionary<string, RateMeter>();
                    context.Application["rateMap"] = ratemap;
                    context.Application["rateMap_cleanup_counter"] = 0;
                }
                string key = "[" + serverUrl.Url + "]x[" + context.Request.UserHostAddress + "]";
                RateMeter rate;
                if (!ratemap.TryGetValue(key, out rate))
                {
                    rate = new RateMeter(serverUrl.RateLimit, serverUrl.RateLimitPeriod);
                    ratemap.TryAdd(key, rate);
                }
                if (!rate.click())
                {
                    log(TraceLevel.Warning, " Pair " + key + " is throttled to " + serverUrl.RateLimit + " requests per " + serverUrl.RateLimitPeriod + " minute(s). Come back later.");
                    sendErrorResponse(context.Response, "This is a metered resource, number of requests have exceeded the rate limit interval.", "Unable to proxy request for requested resource", (System.Net.HttpStatusCode)429);
                    return;
                }

                //making sure the rateMap gets periodically cleaned up so it does not grow uncontrollably
                int cnt = (int)context.Application["rateMap_cleanup_counter"];
                cnt++;
                if (cnt >= CLEAN_RATEMAP_AFTER)
                {
                    cnt = 0;
                    cleanUpRatemap(ratemap);
                }
                context.Application["rateMap_cleanup_counter"] = cnt;
            }
        }

        //readying body (if any) of POST request
        byte[] postBody = readRequestPostBody(context);
        string post = System.Text.Encoding.UTF8.GetString(postBody);

        System.Net.NetworkCredential credentials = null;
        string requestUri = url;
        bool hasClientToken = false;
        string token = string.Empty;
        string tokenParamName = null;

        if (!url.StartsWith("http")) {
            if (restFunction != "") {
                requestUri = serverUrl.Url + "/" + restFunction + "?" + queryString;
            } else {
                requestUri = serverUrl.Url + "?" + queryString;
            }
        }

        else if ((serverUrl.HostRedirect != null) && (serverUrl.HostRedirect != string.Empty))
        {
            requestUri = serverUrl.HostRedirect + new Uri(requestUri).PathAndQuery;
        }

        if (serverUrl.Domain != null)
        {
            credentials = new System.Net.NetworkCredential(serverUrl.Username, serverUrl.Password, serverUrl.Domain);
        }
        // If the Url is configured with httpBasicAuth=true in proxy.config, create new credentials without domain
        if (serverUrl.HttpBasicAuth != null && serverUrl.HttpBasicAuth == true)
        {
            credentials = new System.Net.NetworkCredential(serverUrl.Username, serverUrl.Password);
        }
        else if (!isWMTS)
        {
            //if token comes with client request, it takes precedence over token or credentials stored in configuration
            hasClientToken = requestUri.Contains("?token=") || requestUri.Contains("&token=") || post.Contains("?token=") || post.Contains("&token=");

            if (!hasClientToken)
            {
                // Get new token and append to the request.
                // But first, look up in the application scope, maybe it's already there:
                token = (String)context.Application["token_for_" + serverUrl.Url];
                bool tokenIsInApplicationScope = !String.IsNullOrEmpty(token);

                //if still no token, let's see if there is an access token or if are credentials stored in configuration which we can use to obtain new token
                if (!tokenIsInApplicationScope)
                {
                    token = serverUrl.AccessToken;
                    if (String.IsNullOrEmpty(token))
                        token = getNewTokenIfCredentialsAreSpecified(serverUrl, requestUri);
                }

                if (!String.IsNullOrEmpty(token) && !tokenIsInApplicationScope)
                {
                    //storing the token in Application scope, to do not waste time on requesting new one untill it expires or the app is restarted.
                    context.Application.Lock();
                    context.Application["token_for_" + serverUrl.Url] = token;
                    context.Application.UnLock();
                }

                //name by which token parameter is passed (if url actually came from the list)
                tokenParamName = serverUrl != null ? serverUrl.TokenParamName : null;

                if (String.IsNullOrEmpty(tokenParamName))
                    tokenParamName = "token";
            }
        }

        //forwarding original request
        System.Net.WebResponse serverResponse = null;
        try {
            serverResponse = forwardToServer(context, addTokenToUri(requestUri, token, tokenParamName), postBody, credentials);
        } catch (System.Net.WebException webExc) {

            string errorMsg = webExc.Message + " " + url;
            log(TraceLevel.Error, errorMsg);

            if (webExc.Response != null)
            {
                copyHeaders(webExc.Response as System.Net.HttpWebResponse, context.Response);

                using (Stream responseStream = webExc.Response.GetResponseStream())
                {
                    byte[] bytes = new byte[32768];
                    int bytesRead = 0;

                    while ((bytesRead = responseStream.Read(bytes, 0, bytes.Length)) > 0)
                    {
                        responseStream.Write(bytes, 0, bytesRead);
                    }

                    context.Response.StatusCode = (int)(webExc.Response as System.Net.HttpWebResponse).StatusCode;
                    context.Response.OutputStream.Write(bytes, 0, bytes.Length);
                }
            }
            else
            {
                System.Net.HttpStatusCode statusCode = System.Net.HttpStatusCode.InternalServerError;
                sendErrorResponse(context.Response, null, errorMsg, statusCode);
            }
            return;
        }

        if (string.IsNullOrEmpty(token) || hasClientToken)
            //if token is not required or provided by the client, just fetch the response as is:
            fetchAndPassBackToClient(serverResponse, response, true);
        else {
            //credentials for secured service have come from configuration file:
            //it means that the proxy is responsible for making sure they were properly applied:

            //first attempt to send the request:
            bool tokenRequired = fetchAndPassBackToClient(serverResponse, response, false);


            //checking if previously used token has expired and needs to be renewed
            if (tokenRequired) {
                log(TraceLevel.Info, "Renewing token and trying again.");
                //server returned error - potential cause: token has expired.
                //we'll do second attempt to call the server with renewed token:
                token = getNewTokenIfCredentialsAreSpecified(serverUrl, requestUri);
                serverResponse = forwardToServer(context, addTokenToUri(requestUri, token, tokenParamName), postBody);

                //storing the token in Application scope, to do not waste time on requesting new one untill it expires or the app is restarted.
                context.Application.Lock();
                context.Application["token_for_" + serverUrl.Url] = token;
                context.Application.UnLock();

                fetchAndPassBackToClient(serverResponse, response, true);
            }
        }

        // Use instead of response.End() to avoid the "Exception thrown: 'System.Threading.ThreadAbortException' in mscorlib.dll" error
        // that appears in the output of Visual Studio.  response.End() appears to only really be necessary if you need to end the thread immediately
        // (i.e. no more code is processed).  Since this call is at the end of the main subroutine we can safely call ApplicationInstance.CompleteRequest()
        // and avoid unnecessary exceptions.
        // Sources:
        // http://stackoverflow.com/questions/14590812/what-is-the-difference-between-use-cases-for-using-response-endfalse-vs-appl
        // http://weblogs.asp.net/hajan/why-not-to-use-httpresponse-close-and-httpresponse-end
        // http://stackoverflow.com/questions/1087777/is-response-end-considered-harmful

        context.ApplicationInstance.CompleteRequest();
    }

    public bool IsReusable {
        get { return true; }
    }

/**
* Private
*/

    private StreamReader getStreamReader(MemoryStream ms, Stream byteStream, bool isXML, string responseEncoding)
    {
        bool responseContainsEncodingString = (responseEncoding == "" ? false : true);

        if (isXML && responseContainsEncodingString)
            return new StreamReader(ms,System.Text.Encoding.GetEncoding(responseEncoding));
        if (isXML && !responseContainsEncodingString)
            return new StreamReader(ms);
        return new StreamReader(byteStream);
    }

    private byte[] readRequestPostBody(HttpContext context) {
        if (context.Request.InputStream.Length > 0) {
            byte[] bytes = new byte[context.Request.InputStream.Length];
            context.Request.InputStream.Read(bytes, 0, (int)context.Request.InputStream.Length);
            return bytes;
        }
        return new byte[0];
    }

    private System.Net.WebResponse forwardToServer(HttpContext context, string uri, byte[] postBody, System.Net.NetworkCredential credentials = null)
    {
        return
            postBody.Length > 0?
            doHTTPRequest(uri, postBody, "POST", context.Request.Headers["referer"], context.Request.ContentType, credentials):
            doHTTPRequest(uri, context.Request.HttpMethod, credentials);
    }

    /// <summary>
    /// Attempts to copy all headers from the fromResponse to the the toResponse.
    /// </summary>
    /// <param name="fromResponse">The response that we are copying the headers from</param>
    /// <param name="toResponse">The response that we are copying the headers to</param>
    private void copyHeaders(System.Net.WebResponse fromResponse, HttpResponse toResponse)
    {
        foreach (var headerKey in fromResponse.Headers.AllKeys)
        {
            switch (headerKey.ToLower())
            {
                case "content-type":
                    log(TraceLevel.Verbose, "Content-type from server: " + fromResponse.ContentType );
                    continue;
                case "transfer-encoding":
                case "accept-ranges":   // Prevent requests for partial content
                case "access-control-allow-origin":
                case "access-control-allow-credentials":
                case "access-control-expose-headers":
                case "access-control-max-age":
                    continue;
                default:
                    toResponse.AddHeader(headerKey, fromResponse.Headers[headerKey]);
                    log(TraceLevel.Verbose, "Adding header " + headerKey + " with value " + fromResponse.Headers[headerKey]);
                    break;
            }
        }
        //TODO: Quick hack if portal complains about this 2017-05-26
        if (toResponse.Headers["Access-Control-Allow-Credentials"] == null && toResponse.Headers["access-control-allow-credentials"] == null)
        {
            toResponse.AddHeader("Access-Control-Allow-Credentials", "true");
        }
        // Reset the content-type for OGC WMS - issue #367
        // Note: this might not be what everyone expects, but it helps some users
        // TODO: make this configurable
        if (fromResponse.ContentType.Contains("application/vnd.ogc.wms_xml")) {
            toResponse.ContentType = "text/xml";
            log(TraceLevel.Verbose, "Adjusting Content-Type for WMS OGC: " + fromResponse.ContentType );
        } else {
            toResponse.ContentType = fromResponse.ContentType;
        }
    }

    private bool fetchAndPassBackToClient(System.Net.WebResponse serverResponse, HttpResponse clientResponse, bool ignoreAuthenticationErrors) {
        if (serverResponse != null) {
            MemoryStream ms = new MemoryStream();
            bool isXML = false;
          
            using (Stream byteStream = serverResponse.GetResponseStream()) {

                // If the server response is XML where gonna peek at it to find the encoding
                // in the XML header, but then we need to seek back to the beginning of the stream
                // and that's not possible with the object from GetResponseStream
                // So we will create a copy in the form of a MemoryStream, which we can seek in
                // I only do this if the response type is XML, because that's where I saw the issue
                // and it feels unnecessary to do it with all responses.
                if (serverResponse.ContentType.Contains("xml")) {
                    isXML = true;
                    int count = 0;
                    do
                    {
                        byte[] buf = new byte[1024];
                        count = byteStream.Read(buf, 0, 1024);
                        ms.Write(buf, 0, count);
                    } while(byteStream.CanRead && count > 0);

                    ms.Seek(0, SeekOrigin.Begin);
                }
                bool responseContainsEncodingString = false;
                // Text response
                if (serverResponse.ContentType.Contains("text") ||
                    serverResponse.ContentType.Contains("json") ||
                    isXML) {

                        string responseEncoding = "";

                    if (isXML) {
                        log(TraceLevel.Verbose, "Response is XML ");
                        StreamReader sr = new StreamReader(ms);
                            char[] buffer = new char[400];
                            int readBytes = sr.Read(buffer,0,400);
                            log(TraceLevel.Verbose, "Read bytes from memory stream: " + readBytes);
                            if (readBytes > 0)
                            {
                                string lookAhead = new string(buffer);
                                string pattern = @"encoding=""([A-Za-z0-9-]+)""";
                                Match m = Regex.Match(lookAhead,pattern);
                                if (m.Success) {
                                    responseEncoding = m.Groups[1].Value;
                                
                                    //clientResponse.Charset = "";
                                    log(TraceLevel.Verbose, "Response encoding: " + responseEncoding);
                                }
                                else {
                                    log(TraceLevel.Verbose, "No success :( ");
                                }
                            }
                        ms.Seek(0, SeekOrigin.Begin);
                    }

                    using (StreamReader sr = getStreamReader(ms,byteStream,isXML,responseEncoding)) {
                        if (serverResponse.ContentType.Contains("xml")) {
                            log(TraceLevel.Verbose, "Getting XML response from " + serverResponse.ResponseUri);

                        }
                        string pattern = "";
                        string strResponse = sr.ReadToEnd();
						
						if (this.changeEncodingToUTF8)
						{
							pattern = @"encoding=""([A-Za-z0-9-]+)""";
							foreach (Match m in Regex.Matches(strResponse, pattern)) {
								strResponse = strResponse.Replace(m.ToString(), "encoding=\"utf-8\"");
							}
							pattern = "";
						}

                        if (this.wmsResourceRewrite) {
                            pattern = @"<OnlineResource.*href=""([^\""]+)";
                            string urlToReplace = "";
                            foreach (Match m in Regex.Matches(strResponse, pattern)) {
                                urlToReplace = m.Groups[1].Value;
                                if (urlToReplace != "") break;
                            }
                            if (proxy_url != "" && urlToReplace != "") {
                                strResponse = strResponse.Replace(urlToReplace, proxy_url + requestKey);
                            }

							
							pattern = @"<ows:Get.*href=""([^\""?]+)";
                            urlToReplace = "";
                            foreach (Match m in Regex.Matches(strResponse, pattern)) {
                                urlToReplace = m.Groups[1].Value;
                                if (urlToReplace != "") break;
                            }
                            if (proxy_url != "" && urlToReplace != "") {
								if (!isWMTS)
									strResponse = strResponse.Replace(urlToReplace, proxy_url + requestKey);
								else
									strResponse = strResponse.Replace(urlToReplace, proxy_url + requestKey + "/");
                            }
		//replace epsg with EPSG
		            strResponse = strResponse.Replace("epsg:", "EPSG:");
                        }
						
						bool bboxFlipped = false;

                        if (this.flipWmsBboxCoords) {
							pattern = @"<ows:LowerCorner>(-?[0-9]\d*\.[0-9]\d*)\s(-?[0-9]\d*\.[0-9]\d*)<\/ows:LowerCorner>";
                            MatchCollection mc = Regex.Matches(strResponse, pattern);
                            if (mc != null && mc.Count > 0 && mc[0] != null) {
								bboxFlipped = true;
								for (int i = 0; i < mc.Count; i++)
								{
									Match m = mc[i];
									//Console.WriteLine(m.Groups[1].Value +" index: " + m.Index);
									String origBbox = String.Format(@"<ows:LowerCorner>{0} {1}</ows:LowerCorner>", m.Groups[1].Value, m.Groups[2].Value); 
									String newBbox = String.Format(@"<ows:LowerCorner>{1} {0}</ows:LowerCorner>", m.Groups[1].Value, m.Groups[2].Value);
									strResponse = strResponse.Replace(origBbox, newBbox);
								}
                            }

							pattern = @"<ows:UpperCorner>(-?[0-9]\d*\.[0-9]\d*)\s(-?[0-9]\d*\.[0-9]\d*)<\/ows:UpperCorner>";
								mc = Regex.Matches(strResponse, pattern);
								if (mc != null && mc.Count > 0 && mc[0] != null) {
									for (int i = 0; i < mc.Count; i++)
									{
										Match m = mc[i];
										//Console.WriteLine(m.Groups[1].Value +" index: " + m.Index);
										String origBbox = String.Format(@"<ows:UpperCorner>{0} {1}</ows:UpperCorner>", m.Groups[1].Value, m.Groups[2].Value); 
										String newBbox = String.Format(@"<ows:UpperCorner>{1} {0}</ows:UpperCorner>", m.Groups[1].Value, m.Groups[2].Value);
										strResponse = strResponse.Replace(origBbox, newBbox);
									}
								}
                        }
						
						/* This code is only needed if the wmts does not have LowerCorner UpperCorner bounding box,
						* But only topLeftCorner */
						
						if (this.flipWmsBboxCoords && this.isWMTS && !bboxFlipped) {
							pattern = @"<TopLeftCorner>(-?\d*\.\d*)\s(-?\d*\.\d*)<\/TopLeftCorner>";
                            MatchCollection mc = Regex.Matches(strResponse, pattern);
							String origBbox;
							String newBbox;
							Match m;
							for (int i = 0; i < mc.Count; i++)
							{
								m = mc[i];
								origBbox = String.Format(@"<TopLeftCorner>{0} {1}</TopLeftCorner>", m.Groups[1].Value, m.Groups[2].Value); 
								newBbox = String.Format(@"<TopLeftCorner>{1} {0}</TopLeftCorner>", m.Groups[1].Value, m.Groups[2].Value);
                                strResponse = strResponse.Replace(origBbox, newBbox);
                              
                            }
                        }
						
						
                        //log(TraceLevel.Verbose, strResponse);
                        if (
                            !ignoreAuthenticationErrors
                            && strResponse.Contains("error")
                            && Regex.Match(strResponse, "\"code\"\\s*:\\s*49[89]").Success
                        )
                            return true;

                        //Copy the header info and the content to the reponse to client
                        copyHeaders(serverResponse, clientResponse);
                        clientResponse.Write(strResponse);
                    }
                } else {
                    // Binary response (image, lyr file, other binary file)

                    //Copy the header info to the reponse to client
                    copyHeaders(serverResponse, clientResponse);
                    // Tell client not to cache the image since it's dynamic
                    clientResponse.CacheControl = "no-cache";
                    byte[] buffer = new byte[32768];
                    int read;
                    while ((read = byteStream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        clientResponse.OutputStream.Write(buffer, 0, read);
                    }
                    clientResponse.OutputStream.Close();
                }
                serverResponse.Close();
            }
        }
        return false;
    }

    private System.Net.WebResponse doHTTPRequest(string uri, string method, System.Net.NetworkCredential credentials = null)
    {
        byte[] bytes = null;
        String contentType = null;
        log(TraceLevel.Info, "Sending " + method + " request: " + uri);

        if (method.Equals("POST"))
        {
            String[] uriArray = uri.Split(new char[] { '?' }, 2);
            uri = uriArray[0];
            if (uriArray.Length > 1)
            {
                contentType = "application/x-www-form-urlencoded";
                String queryString = uriArray[1];

                bytes = System.Text.Encoding.UTF8.GetBytes(queryString);
            }
        }

        return doHTTPRequest(uri, bytes, method, PROXY_REFERER, contentType, credentials);
    }

    private System.Net.WebResponse doHTTPRequest(string uri, byte[] bytes, string method, string referer, string contentType, System.Net.NetworkCredential credentials = null)
    { 
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
        System.Net.HttpWebRequest req = (System.Net.HttpWebRequest)System.Net.HttpWebRequest.Create(uri);
        req.ServicePoint.Expect100Continue = false;
        req.Referer = referer;
        req.Method = method;

        // Use the default system proxy
        req.Proxy = SYSTEM_PROXY;

        if (credentials != null)
        {
             req.Credentials = credentials;

            // For now, this is a quick hack.
            // If the credentials do not contain a domain, assume that we are using Basic Authentication
            // Because if Domain is empty in the config, and httpBasicAuth is false (or empty), then credentials = null
            if (credentials.Domain == null)
            {
                log(TraceLevel.Info, "Enabling PreAuthenticate for Basic Authentication");
                req.PreAuthenticate = true;
            }
        }

        if (bytes != null && bytes.Length > 0 || method == "POST") {
            req.Method = "POST";
            req.ContentType = string.IsNullOrEmpty(contentType) ? "application/x-www-form-urlencoded" : contentType;
            if (bytes != null && bytes.Length > 0)
                req.ContentLength = bytes.Length;
            using (Stream outputStream = req.GetRequestStream()) {
                outputStream.Write(bytes, 0, bytes.Length);
            }
        }
        return req.GetResponse();
    }

    private string webResponseToString(System.Net.WebResponse serverResponse) {
        using (Stream byteStream = serverResponse.GetResponseStream()) {
            using (StreamReader sr = new StreamReader(byteStream)) {
                string strResponse = sr.ReadToEnd();
                return strResponse;
            }
        }
    }

    private string getNewTokenIfCredentialsAreSpecified(ServerUrl su, string reqUrl) {
        string token = "";
        string infoUrl = "";

        bool isUserLogin = !String.IsNullOrEmpty(su.Username) && !String.IsNullOrEmpty(su.Password);
        bool isAppLogin = !String.IsNullOrEmpty(su.ClientId) && !String.IsNullOrEmpty(su.ClientSecret);
        if (isUserLogin || isAppLogin) {
            log(TraceLevel.Info, "Matching credentials found in configuration file. OAuth 2.0 mode: " + isAppLogin);
            if (isAppLogin) {
                //OAuth 2.0 mode authentication
                //"App Login" - authenticating using client_id and client_secret stored in config
                su.OAuth2Endpoint = string.IsNullOrEmpty(su.OAuth2Endpoint) ? DEFAULT_OAUTH : su.OAuth2Endpoint;
                if (su.OAuth2Endpoint[su.OAuth2Endpoint.Length - 1] != '/')
                    su.OAuth2Endpoint += "/";
                log(TraceLevel.Info, "Service is secured by " + su.OAuth2Endpoint + ": getting new token...");
                string uri = su.OAuth2Endpoint + "token?client_id=" + su.ClientId + "&client_secret=" + su.ClientSecret + "&grant_type=client_credentials&f=json";
                string tokenResponse = webResponseToString(doHTTPRequest(uri, "POST"));
                token = extractToken(tokenResponse, "token");
                if (!string.IsNullOrEmpty(token))
                    token = exchangePortalTokenForServerToken(token, su);
            } else {
                //standalone ArcGIS Server/ArcGIS Online token-based authentication

                //if a request is already being made to generate a token, just let it go
                if (reqUrl.ToLower().Contains("/generatetoken")) {
                    string tokenResponse = webResponseToString(doHTTPRequest(reqUrl, "POST"));
                    token = extractToken(tokenResponse, "token");
                    return token;
                }

                //lets look for '/rest/' in the requested URL (could be 'rest/services', 'rest/community'...)
                if (reqUrl.ToLower().Contains("/rest/"))
                    infoUrl = reqUrl.Substring(0, reqUrl.IndexOf("/rest/", StringComparison.OrdinalIgnoreCase));

                //if we don't find 'rest', lets look for the portal specific 'sharing' instead
                else if (reqUrl.ToLower().Contains("/sharing/")) {
                    infoUrl = reqUrl.Substring(0, reqUrl.IndexOf("/sharing/", StringComparison.OrdinalIgnoreCase));
                    infoUrl = infoUrl + "/sharing";
                }
                else
                    throw new ApplicationException("Unable to determine the correct URL to request a token to access private resources.");

                if (infoUrl != "") {
                    log(TraceLevel.Info," Querying security endpoint...");
                    infoUrl += "/rest/info?f=json";
                    //lets send a request to try and determine the URL of a token generator
                    string infoResponse = webResponseToString(doHTTPRequest(infoUrl, "GET"));
                    String tokenServiceUri = getJsonValue(infoResponse, "tokenServicesUrl");
                    if (string.IsNullOrEmpty(tokenServiceUri)) {
                        string owningSystemUrl = getJsonValue(infoResponse, "owningSystemUrl");
                        if (!string.IsNullOrEmpty(owningSystemUrl)) {
                            tokenServiceUri = owningSystemUrl + "/sharing/generateToken";
                        }
                    }
                    if (tokenServiceUri != "") {
                        log(TraceLevel.Info," Service is secured by " + tokenServiceUri + ": getting new token...");
                        string uri = tokenServiceUri + "?f=json&request=getToken&referer=" + PROXY_REFERER + "&expiration=60&username=" + su.Username + "&password=" + su.Password;
                        string tokenResponse = webResponseToString(doHTTPRequest(uri, "POST"));
                        token = extractToken(tokenResponse, "token");
                    }
                }


            }
        }
        return token;
    }

    private bool checkWildcardSubdomain(String allowedReferer, String requestedReferer)
    {
        String[] allowedRefererParts = Regex.Split(allowedReferer, "(\\.)");
        String[] refererParts = Regex.Split(requestedReferer, "(\\.)");

        if (allowedRefererParts.Length != refererParts.Length)
        {
            return false;
        }

        int index = allowedRefererParts.Length - 1;
        while (index >= 0)
        {
            if (allowedRefererParts[index].Equals(refererParts[index], StringComparison.OrdinalIgnoreCase))
            {
                index = index - 1;
            }
            else
            {
                if (allowedRefererParts[index].Equals("*"))
                {
                    index = index - 1;
                    continue; //next
                }
                return false;
            }
        }
        return true;
    }

    private bool pathMatched(String allowedRefererPath, String refererPath)
    {
        //If equal, return true
        if (refererPath.Equals(allowedRefererPath))
        {
            return true;
        }

        //If the allowedRefererPath contain a ending star and match the begining part of referer, it is proper start with.
        if (allowedRefererPath.EndsWith("*"))
        {
            String allowedRefererPathShort = allowedRefererPath.Substring(0, allowedRefererPath.Length - 1);
            if (refererPath.ToLower().StartsWith(allowedRefererPathShort.ToLower()))
            {
                return true;
            }
        }
        return false;
    }

    private bool domainMatched(String allowedRefererDomain, String refererDomain)
    {
        if (allowedRefererDomain.Equals(refererDomain)){
            return true;
        }

        //try if the allowed referer contains wildcard for subdomain
        if (allowedRefererDomain.Contains("*")){
            if (checkWildcardSubdomain(allowedRefererDomain, refererDomain)){
                return true;//return true if match wildcard subdomain
            }
        }

        return false;
    }

    private bool protocolMatch(String allowedRefererProtocol, String refererProtocol)
    {
        return allowedRefererProtocol.Equals(refererProtocol);
    }

    private String getDomainfromURL(String url, String protocol)
    {
        String domain = url.Substring(protocol.Length + 3);

        domain = domain.IndexOf('/') >= 0 ? domain.Substring(0, domain.IndexOf('/')) : domain;

        return domain;
    }

    private bool checkReferer(String[] allowedReferers, String referer)
    {
        if (allowedReferers != null && allowedReferers.Length > 0)
        {
            if (allowedReferers.Length == 1 && allowedReferers[0].Equals("*")) return true; //speed-up

            foreach (String allowedReferer in allowedReferers)
            {

		if (referer == allowedReferer) {
                    return true;
                }

                //Parse the protocol, domain and path of the referer
                String refererProtocol = referer.StartsWith("https://") ? "https" : "http";
                String refererDomain = getDomainfromURL(referer, refererProtocol);
                String refererPath = referer.Substring(refererProtocol.Length + 3 + refererDomain.Length);


                String allowedRefererCannonical = null;

                //since the allowedReferer can be a malformed URL, we first construct a valid one to be compared with referer
                //if allowedReferer starts with https:// or http://, then exact match is required
                if (allowedReferer.StartsWith("https://") || allowedReferer.StartsWith("http://"))
                {
                    allowedRefererCannonical = allowedReferer;

                }
                else
                {

                    String protocol = refererProtocol;
                    //if allowedReferer starts with "//" or no protocol, we use the one from refererURL to prefix to allowedReferer.
                    if (allowedReferer.StartsWith("//"))
                    {
                        allowedRefererCannonical = protocol + ":" + allowedReferer;
                    }
                    else
                    {
                        //if the allowedReferer looks like "example.esri.com"
                        allowedRefererCannonical = protocol + "://" + allowedReferer;
                    }
                }

                //parse the protocol, domain and the path of the allowedReferer
                String allowedRefererProtocol = allowedRefererCannonical.StartsWith("https://") ? "https" : "http";
                String allowedRefererDomain = getDomainfromURL(allowedRefererCannonical, allowedRefererProtocol);
                String allowedRefererPath = allowedRefererCannonical.Substring(allowedRefererProtocol.Length + 3 + allowedRefererDomain.Length);

                //Check if both domain and path match
                if (protocolMatch(allowedRefererProtocol, refererProtocol) &&
                        domainMatched(allowedRefererDomain, refererDomain) &&
                        pathMatched(allowedRefererPath, refererPath))
                {
                    return true;
                }
            }
            return false;//no-match
        }
        return true;//when allowedReferer is null, then allow everything
    }

    private string exchangePortalTokenForServerToken(string portalToken, ServerUrl su) {
        //ideally, we should POST the token request
        log(TraceLevel.Info," Exchanging Portal token for Server-specific token for " + su.Url + "...");
        string uri = su.OAuth2Endpoint.Substring(0, su.OAuth2Endpoint.IndexOf("/oauth2/", StringComparison.OrdinalIgnoreCase)) +
             "/generateToken?token=" + portalToken + "&serverURL=" + su.Url + "&f=json";
        string tokenResponse = webResponseToString(doHTTPRequest(uri, "GET"));
        return extractToken(tokenResponse, "token");
    }


    private static void sendPingResponse(HttpResponse response, String version, String config, String log)
    {
        response.AddHeader("Content-Type", "application/json");
        response.AddHeader("Accept-Encoding", "gzip");
        String message = "{ " +
            "\"Proxy Version\": \"" + version + "\"" +
            ", \"Configuration File\": \"" + config + "\"" +
            ", \"Log File\": \"" + log + "\"" +
            "}";
        response.StatusCode = 200;
        response.Write(message);
        response.Flush();
    }

    private static void sendErrorResponse(HttpResponse response, String errorDetails, String errorMessage, System.Net.HttpStatusCode errorCode)
    {
        String message = string.Format("{{\"error\": {{\"code\": {0},\"message\":\"{1}\"", (int)errorCode, errorMessage);
        if (!string.IsNullOrEmpty(errorDetails))
            message += string.Format(",\"details\":[\"message\":\"{0}\"]", errorDetails);
        message += "}}";
        response.StatusCode = (int)errorCode;
        //custom status description for when the rate limit has been exceeded
        if (response.StatusCode == 429) {
            response.StatusDescription = "Too Many Requests";
        }
        //this displays our customized error messages instead of IIS's custom errors
        response.TrySkipIisCustomErrors = true;
        response.Write(message);
        response.Flush();
    }

    private static string getClientIp(HttpRequest request)
    {
        if (request == null)
            return null;
        string remoteAddr = request.ServerVariables["HTTP_X_FORWARDED_FOR"];
        if (string.IsNullOrWhiteSpace(remoteAddr))
        {
            remoteAddr = request.ServerVariables["REMOTE_ADDR"];
        }
        else
        {
            // the HTTP_X_FORWARDED_FOR may contain an array of IP, this can happen if you connect through a proxy.
            string[] ipRange = remoteAddr.Split(',');
            remoteAddr = ipRange[ipRange.Length - 1];
        }
        return remoteAddr;
    }

    private string addTokenToUri(string uri, string token, string tokenParamName) {
        if (!String.IsNullOrEmpty(token))
            uri += uri.Contains("?")? "&" + tokenParamName + "=" + token : "?" + tokenParamName + "=" + token;
        return uri;
    }

    private string extractToken(string tokenResponse, string key) {
        string token = getJsonValue(tokenResponse, key);
        if (string.IsNullOrEmpty(token))
            log(TraceLevel.Error," Token cannot be obtained: " + tokenResponse);
        else
            log(TraceLevel.Info," Token obtained: " + token);
        return token;
    }

    private string getJsonValue(string text, string key) {
        int i = text.IndexOf(key);
        String value = "";
        if (i > -1) {
            value = text.Substring(text.IndexOf(':', i) + 1).Trim();

            value = value.Length > 0 && value[0] == '"' ?
                // Get the rest of a quoted string
                value.Substring(1, Math.Max(0, value.IndexOf('"', 1) - 1)) :
                // Get a string up to the closest comma, bracket, or brace
                value = value.Substring(0,
                    Math.Min(
                        value.Length,
                        Math.Min(
                            indexOf_HighFlag(value, ","),
                            Math.Min(
                                indexOf_HighFlag(value, "]"),
                                indexOf_HighFlag(value, "}")
                            )
                        )
                    )
                );
        }
        return value;
    }

    private int indexOf_HighFlag(string text, string key) {
        int i = text.IndexOf(key);
        if (i < 0) i = Int32.MaxValue;
        return i;
    }

    private void cleanUpRatemap(ConcurrentDictionary<string, RateMeter> ratemap) {
        foreach (string key in ratemap.Keys){
            RateMeter rate = ratemap[key];
            if (rate.canBeCleaned())
                ratemap.TryRemove(key, out rate);
        }
    }

/**
* Static
*/
    private static ProxyConfig getConfig() {
        ProxyConfig config = ProxyConfig.GetCurrentConfig();
        if (config != null)
            return config;
        else
            throw new ApplicationException("The proxy configuration file cannot be found, or is not readable.");
    }

    //writing Log file
    private static void log(TraceLevel logLevel, string msg) {
        string logMessage = string.Format("{0} {1}", DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), msg);

        ProxyConfig config = ProxyConfig.GetCurrentConfig();
        TraceSwitch ts = null;

        if (config.logLevel != null)
        {
            ts = new TraceSwitch("TraceLevelSwitch2", "TraceSwitch in the proxy.config file", config.logLevel);
        }
        else
        {
            ts = new TraceSwitch("TraceLevelSwitch2", "TraceSwitch in the proxy.config file", "Error");
            config.logLevel = "Error";
        }

        Trace.WriteLineIf(logLevel <= ts.Level, logMessage);
    }

    private static object _lockobject = new object();

}

class LogTraceListener : TraceListener
{
    private static object _lockobject = new object();
    public override void Write(string message)
    {
        //Only log messages to disk if logFile has value in configuration, otherwise log nothing.
        ProxyConfig config = ProxyConfig.GetCurrentConfig();

        if (config.LogFile != null)
        {
            string log = config.LogFile;
            if (!log.Contains("\\") || log.Contains(".\\"))
            {
                if (log.Contains(".\\")) //If this type of relative pathing .\log.txt
                {
                    log = log.Replace(".\\", "");
                }
                string configDirectory = HttpContext.Current.Server.MapPath("proxy.config"); //Cannot use System.Web.Hosting.HostingEnvironment.ApplicationPhysicalPath b/ config may be in a child directory
                string path = configDirectory.Replace("proxy.config", "");
                log = path + log;
            }

            lock (_lockobject)
            {
                using (StreamWriter sw = File.AppendText(log))
                {
                    sw.Write(message);
                }
            }
        }
    }


    public override void WriteLine(string message)
    {
        //Only log messages to disk if logFile has value in configuration, otherwise log nothing.
        ProxyConfig config = ProxyConfig.GetCurrentConfig();
        if (config.LogFile != null)
        {
            string log = config.LogFile;
            if (!log.Contains("\\") || log.Contains(".\\"))
            {
                if (log.Contains(".\\")) //If this type of relative pathing .\log.txt
                {
                    log = log.Replace(".\\", "");
                }
                string configDirectory = HttpContext.Current.Server.MapPath("proxy.config"); //Cannot use System.Web.Hosting.HostingEnvironment.ApplicationPhysicalPath b/ config may be in a child directory
                string path = configDirectory.Replace("proxy.config", "");
                log = path + log;
            }

            lock (_lockobject)
            {
                using (StreamWriter sw = File.AppendText(log))
                {
                    sw.WriteLine(message);
                }
            }
        }
    }

}


[XmlRoot("ProxyConfig")]
public class ProxyConfig
{
    private static object _lockobject = new object();
    public static ProxyConfig LoadProxyConfig(string fileName) {
        ProxyConfig config = null;
        lock (_lockobject) {
            if (System.IO.File.Exists(fileName)) {
                XmlSerializer reader = new XmlSerializer(typeof(ProxyConfig));
                using (System.IO.StreamReader file = new System.IO.StreamReader(fileName)) {
                    try {
                        config = (ProxyConfig)reader.Deserialize(file);
                    }
                    catch (Exception ex) {
                        throw ex;
                    }
                }
            }
        }
        return config;
    }

    public static ProxyConfig GetCurrentConfig() {
        ProxyConfig config = HttpRuntime.Cache["proxyConfig"] as ProxyConfig;
        if (config == null) {
            string fileName = HttpContext.Current.Server.MapPath("proxy.config");
            config = LoadProxyConfig(fileName);
            if (config != null) {
                CacheDependency dep = new CacheDependency(fileName);
                HttpRuntime.Cache.Insert("proxyConfig", config, dep);
            }
        }
        return config;
    }

    //referer
    //create an array with valid referers using the allowedReferers String that is defined in the proxy.config
    public static String[] GetAllowedReferersArray()
    {
        if (allowedReferers == null)
            return null;

        return allowedReferers.Split(',');
    }

    //referer
    //check if URL starts with prefix...
    public static bool isUrlPrefixMatch(String prefix, String uri)
    {

        return uri.ToLower().StartsWith(prefix.ToLower()) ||
                    uri.ToLower().Replace("https://", "http://").StartsWith(prefix.ToLower()) ||
                    uri.ToLower().Substring(uri.IndexOf("//")).StartsWith(prefix.ToLower());
    }

    ServerUrl[] serverUrls;
    public String logFile;
    public String logLevel;
    bool mustMatch;
    //referer
    static String allowedReferers;

    [XmlArray("serverUrls")]
    [XmlArrayItem("serverUrl")]
    public ServerUrl[] ServerUrls {
        get { return this.serverUrls; }
        set
        {
            this.serverUrls = value;
        }
    }
    [XmlAttribute("mustMatch")]
    public bool MustMatch {
        get { return mustMatch; }
        set
        { mustMatch = value; }
    }

    //logFile
    [XmlAttribute("logFile")]
    public String LogFile
    {
        get { return logFile; }
        set
        { logFile = value; }
    }

    //logLevel
    [XmlAttribute("logLevel")]
    public String LogLevel
    {
        get { return logLevel; }
        set
        { logLevel = value; }
    }


    //referer
    [XmlAttribute("allowedReferers")]
    public string AllowedReferers
    {
        get { return allowedReferers; }
        set
        {
            allowedReferers = Regex.Replace(value, @"\s", "");
        }
    }

    public ServerUrl GetConfigServerUrl(string uri) {
        //split both request and proxy.config urls and compare them
        string[] uriParts = uri.Split(new char[] {'/','?'}, StringSplitOptions.RemoveEmptyEntries);
        string[] configUriParts = new string[] {};
        
        foreach (ServerUrl su in serverUrls) {
            if (su.Key == null && !uri.StartsWith("http"))
                continue;
            //if a relative path is specified in the proxy.config, append what's in the request itself
            if (!uri.StartsWith("http"))
            {
                if (su.Key.Equals(uri)) {
                    return su;
                }
                // This line is removed, so all proxied urls must start with http/https...
                //su.Url = su.Url.Insert(0, uriParts[0]);
            }
            else {

                configUriParts = su.Url.Split(new char[] { '/','?' }, StringSplitOptions.RemoveEmptyEntries);
                
                //if the request has less parts than the config, don't allow
                if (configUriParts.Length > uriParts.Length) continue;

                int i = 0;
                for (i = 0; i < configUriParts.Length; i++) {

                    if (!configUriParts[i].ToLower().Equals(uriParts[i].ToLower())) {
                        break;
                    }
                }
                if (i == configUriParts.Length) {
                    //if the urls don't match exactly, and the individual matchAll tag is 'false', don't allow
                    if (configUriParts.Length == uriParts.Length || !su.MatchAll)
                        return su;
                }
            }
        }

        if (!mustMatch)
        {
            return new ServerUrl(uri);
        }
        else
        {
            throw new ArgumentException("Proxy has not been set up for this URL. Make sure there is a serverUrl in the configuration file that matches: " + uri);
        }
    }
}

public class ServerUrl {
    string key;
    string url;
    string hostRedirect;
    bool matchAll;
    string oauth2Endpoint;
    string domain;
    string username;
    string password;
    string clientId;
    string clientSecret;
    string accessToken;
    string tokenParamName;
    string rateLimit;
    string rateLimitPeriod;
    bool httpBasicAuth;
    bool forceHttp;
    bool wmsResourceRewrite;
	bool changeEncodingToUTF8;
    bool flipWmsBboxCoords;
	bool isWMTS;

    private ServerUrl()
    {
    }

    public ServerUrl(String url)
    {
        this.url = url;
    }

    [XmlAttribute("key")]
    public string Key {
        get { return key; }
        set { key = value; }
    }

    [XmlAttribute("url")]
    public string Url {
        get { return url; }
        set { url = value; }
    }
    [XmlAttribute("hostRedirect")]
    public string HostRedirect
    {
        get { return hostRedirect; }
        set { hostRedirect = value; }
    }
    [XmlAttribute("matchAll")]
    public bool MatchAll {
        get { return matchAll; }
        set { matchAll = value; }
    }
    [XmlAttribute("oauth2Endpoint")]
    public string OAuth2Endpoint {
        get { return oauth2Endpoint; }
        set { oauth2Endpoint = value; }
    }
    [XmlAttribute("domain")]
    public string Domain
    {
        get { return domain; }
        set { domain = value; }
    }
    [XmlAttribute("username")]
    public string Username {
        get { return username; }
        set { username = value; }
    }
    [XmlAttribute("password")]
    public string Password {
        get { return password; }
        set { password = value; }
    }
    [XmlAttribute("clientId")]
    public string ClientId {
        get { return clientId; }
        set { clientId = value; }
    }
    [XmlAttribute("clientSecret")]
    public string ClientSecret {
        get { return clientSecret; }
        set { clientSecret = value; }
    }
    [XmlAttribute("accessToken")]
    public string AccessToken {
        get { return accessToken; }
        set { accessToken = value; }
    }
    [XmlAttribute("tokenParamName")]
    public string TokenParamName {
        get { return tokenParamName; }
        set { tokenParamName = value; }
    }
    [XmlAttribute("rateLimit")]
    public int RateLimit {
        get { return string.IsNullOrEmpty(rateLimit)? -1 : int.Parse(rateLimit); }
        set { rateLimit = value.ToString(); }
    }
    [XmlAttribute("rateLimitPeriod")]
    public int RateLimitPeriod {
        get { return string.IsNullOrEmpty(rateLimitPeriod)? 60 : int.Parse(rateLimitPeriod); }
        set { rateLimitPeriod = value.ToString(); }
    }
    // New attribute to indicate whether or not the configured URL requires basic authentication
    [XmlAttribute("httpBasicAuth")]
    public bool HttpBasicAuth
    {
        get { return httpBasicAuth; }
        set { httpBasicAuth = value; }
    }
    [XmlAttribute("forceHttp")]
    public bool ForceHttp
    {
        get { return forceHttp; }
        set { forceHttp = value; }
    }
    [XmlAttribute("wmsResourceRewrite")]
    public bool WMSResourceRewrite
    {
        get { return wmsResourceRewrite; }
        set { wmsResourceRewrite = value; }
    }
	[XmlAttribute("changeEncodingToUTF8")]
    public bool ChangeEncodingToUTF8
    {
        get { return changeEncodingToUTF8; }
        set { changeEncodingToUTF8 = value; }
    }
    [XmlAttribute("flipWmsBboxCoords")]
    public bool FlipWMSBboxCoords
    {
        get { return flipWmsBboxCoords; }
        set { flipWmsBboxCoords = value; }
    }
	[XmlAttribute("isWMTS")]
	public bool IsWMTS
	{
		get { return isWMTS; }
		set { isWMTS = value; }
	}
}
