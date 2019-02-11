ArcGIS Resource Proxy
=====================

## Introduction
This resource proxy is a fork of the [Esri Resource Proxy](https://github.com/Esri/resource-proxy) so please see that repo for full documentation.
This document will focus on changes made and how to use it with certain Swedish WMS resource.

*READ THROUGH THIS WHOLE DOCUMENT BEFORE USING THE PROXY*

## Disclaimer
This code has not been thoroughly tested for bugs, security issues and performance.
This is not an official Esri or Esri Sweden release, and was created as a quickfix for accessing WMS services from the swedish Lantmäteriet, which are protected by Http Basic authentication, something that is not supported by default in ArcGIS Online or ArcGIS Enterprise (Portal for ArcGIS).

Additionally, it fixes a bug with character encoding from certain WMS-answers.

## Technical overview
### Basic auth problem with ArcGIS Online and Portal
In ArcGIS Online and Portal, credentials cannot be saved for services requiring Http Basic authenticaton.
This is because that negotiation is between the browser (client) and webserver.

Theoretically, this could be implemented in the built-in proxy in ArcGIS Online and Portal, but it is complex and might cause other issues if not done with the uttermost care and thinking through of all the possible scenarios.

### How to solve the basic auth problem
The default resource-proxy can be quite easily modified to send credentials with basic authentication, but when working with WMS-services you might (always?) get a resource URL back from the GetCapabilites XML, and that resource URL will be unproxied, so the requests will not go through the proxy when getting the images (GetMap request) from the WMS, and thus the browser will ask for credentials (at best) or silently fail.

To get around that problem I added the property **wmsResourceRewrite** to the config file (proxy.config). When set to **true**, this option will look for the <OnlineResource> tag in the GetCapabilities WMS and rewrite the href attribute to include the proxy-URL first i.e.:
```
 xlink:href="https://[originalmachine]/service/WMS"/
 will be rewritten as
 xlink:href="https://[yourmachine]/tokenproxy/mySecretToken"/>
```
*The URL format above will be explained soon.*

So what we've done so far is solved the basic auth problem, however

### The Question mark issue
I have not had time to research whether this is a problem in general with browsers (ajax request) or specifically with ArcGIS Online / Portal, but some things I've seen lead me to believe that this might be browser-based, or something I am not understanding fully.

The problem is that with the regular resource-proxy, even when modified to work with Basic Authentication, it will require you to add a OGC WMS layer in this form in ArcGIS Online:
```
https://[yourmachine]proxy/proxy.ashx?https://[originalmachine]/services/WMS
```
This will cause a request like this to be sent (the first proxy? is non-optional in ArcGIS Online):
```
proxy?https://[yourmachine]proxy/proxy.ashx?https://[originalmachine]/services/WMS=&request=SERVICE=WMS&
```
It seems like the browser is replacing the third question mark (the last) with an equal and ampersand sign (=&), because what I would expect to be sent is the following request:
```
proxy?https://[yourmachine]proxy/proxy.ashx?https://[originalmachine]/services/WMS?request=SERVICE=WMS&
```
Even in Portal, where, in my case, no builtin proxy is used, the last question mark will be converted to an equal + ampersand (=&)

### How to solve the question mark issue
To solve this issue, I hade to use the URLRewrite module (downloadable) in IIS, so that a user can access a specific service, through the proxy, using a key-value (a.k.a. Token) instead of the full URL, so the proxy-address to a specific server will be:
```
https://[yourmachine]proxy/MyVerySecretToken
```
which will be rewritten as
```
https://[yourmachine]tokenproxy/proxy.ashx?url=MyVerySecretToken&restFunction=XXXXX
```
The restFunction parameter is there because I noticed that it was needed when calling regular ArcGIS Map Services.
Of course you can call them by using the old syntax (if you don't want tokenized URL:s for them), but there is another scenario which I added support for...

### The http / https issue
I found out that some users wanted to use an open ArcGIS Map Service, with no login required, but only available through http
When adding such a service in AGOL or Portal which are HTTPS only, the service itself will have its URL converted to https (even though a proxy is used),
so I added the config keyword **forceHttp** (boolean). With this set, the proxy will call the service with http instead of https, even if it recieves an https URL.
Anyway, if you are using a regular ArcGIS Map Service, it will usually have parameters in the form of:
```
http://[yourmachine]proxy/MyVerySecretToken/export?f=image.....
```
so the URLRewrite will first extract the token (MyVerySecretToken) but also the function (export) so we can build a proper URL inside the proxy code, to send the request to.

### The encoding issue
**Added a quick hack fix for this**: look at setting parameter changeEncodingToUTF8
I also noticed that with some WMS Services, the server will not have a content encoding set in the serverResponse, but only in the GetCapabilites XML header
```
<?xml version="1.0" encoding="ISO-8859-1" standalone="no"?>
```
The answer to the client however, would be sent as UTF-8 for some reason (seems like that's the default internal representation in DotNet for strings/streams etc.??).


### Solution to the encoding issue
Without digging to deep into the understanding of HTTP headers, and what's expected of them, I found out by trial-and-error that I need to peek ahead in the response stream and
extract the encoding from the XML header and then again, when fetching the response stream, fetch it with that encoding. 
I found no working way to properly encode the response string after fetching the response stream into a Stream object. I've never been on good terms with converting between different
encodings :)

## Instructions

* Download and unzip the .zip file or clone the repository.
* Install the contents as a .NET Web Application, specifying a .NET 4.0 application pool or later. For example using the following steps:
    * Open IIS Manager
    * If you put the files in a **tokeproxy** folder within wwwroot, right-click it and select "Convert to Application".
    * Make sure the "Application pool" is at least 4.0.
* Install [URLRewrite](https://www.iis.net/downloads/microsoft/url-rewrite) for IIS
* Test that the proxy is installed and available:
```
http://[yourmachine]/tokenproxy/proxy.ashx?ping
```
* Configure URL-rewriting for the website (not the application) according to this image:
![Image of URL-rewrite](https://github.com/sverkerEsriSE/resource-proxy-tokens/raw/master/url_rewrite.png)
Replace the *proxy*-part in the start of Pattern if you want another URL to the proxy than http://[yourmachine]/proxy
Replace the *tokenproxy*-part in the Rewrite URL if you put the files in a folder other than tokenproxy under wwwroot
* Troubleshooting: If you get an error message 404.3, it's possible that ASP.NET have not been set up. On Windows 8, go to "Turn Windows features on or off" -> "Internet Information Services" -> "World Wide Web Services" -> "Application Development Features" -> "ASP.NET 4.5".
* Edit the proxy.config file in a text editor to set up your [proxy configuration settings](README.md#proxy-configuration-settings).
* Security tip: By default, the proxy.config allows any referrer. To lock this down, replace the  ```*``` in the ```allowedReferers``` property with your own application URLs.

### Web.config sample for URLRewrite
This is the *Web.config* file found in my c:\wwwroot after adding the proxy pattern
```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <rewrite>
            <rules>
                <rule name="ProxyRule">
                    <match url="^proxy\/([A-Za-z0-9]*)(\/*)([^?]*)" />
                    <action type="Rewrite" url="tokenproxy/proxy.ashx?url={R:1}&amp;restFunction={R:3}" appendQueryString="true" />
                </rule>
            </rules>
        </rewrite>
    </system.webServer>
</configuration>
```

## Security concerns
Since a proxy exposed on the Internet can be accessible by anyone knowing the URL, and therefore also the services provided by the WMS we recommend that
1. Use another form of protection available in IIS (Windows Authentication for example)
2. Use SSL and a strong token (at least the URL will be encrypted between the endpoints)
3. Limit by another form, like IP, Referer, rate limit etc.

## Proxy Configuration Settings

See the XML configuration properties listed below.

### New parameters in this tokenized version:
* *key* : Characters *[A-Za-z0-9_]* - the token with which you want to access the **url** (which must also be specified for the `<serverUrl>`)
* *httpBasicAuth* : can be *true* or *false* - indicates if the password uses http basic auth. Specify **username** and **password** also
* *forceHttp* : if your site is https only, but you want to access services which are http only, and AGOL or Portal keeps rewriting the url with https
* *wmsResourceRewrite* : set to *true* if the GetCapabilites provides OnlineResource URL:s which also requires the same http basic auth as the GetCapabilities request
* *changeEncodingToUTF8* : set to *true* if you are getting weird characters in ArcMap instead of swedish characters like å,ä,ö
* *flipWmsBboxCoords* : set to *true* if you are using a WMS/WMTS which sends the bounding box coordinates in the wrong order (you get no tiles loading in AGOL)
* *isWMTS* : set to *true* if you are using a WMTS

### Standard parameters from the Esri resource-proxy version
* Use the ProxyConfig tag to specify the following proxy level settings.
    * **mustMatch="true"** : When true only the sites listed using serverUrl will be proxied. Set to false to proxy any site, which can be useful in testing. However, we recommend setting it to "true" for production sites.
    * **allowedReferers="http://server.com/app1,http://server.com/app2"** : A comma-separated list of referer URLs. Only requests coming from referers in the list will be proxied. See https://github.com/Esri/resource-proxy/issues/282 for detailed usage.
    * **logFile="proxylog.txt"** : When a logFile is specified, the proxy will log messages to this file. *N.B.: The folder containing the logFile must be writable by the web server.* If a path is not specified, the .Net proxy uses the folder where the proxy.config file is found. (The Java proxy uses java.util.logging.FileHandler to open the file; the PHP proxy uses fopen to open the file.)
    * **logLevel="Error"** : An optional flag indicating the level of detail to write to the logFile. Flags for each of the various languages are listed below.
        *  .Net levels are "Error", "Warning", "Info", and "Verbose" in order from fewest to most messages; the default is "Error".
* Add a new `<serverUrl>` entry for each service that will use the proxy. The proxy.config allows you to use the serverUrl tag to specify one or more ArcGIS Server services that the proxy will forward requests to. The serverUrl tag has the following attributes:
    * **url**: Location of the ArcGIS Server service (or other URL) to proxy. Specify either the specific URL or the root (in which case you should set matchAll="false").
    * **matchAll="true"**: When true all requests that begin with the specified URL are forwarded. Otherwise, the URL requested must match exactly.
    * **username**: Username to use when requesting a token - if needed for ArcGIS Server token based authentication.
    * **password**: Password to use when requesting a token - if needed for ArcGIS Server token based authentication.
    * **tokenServiceUri**: If username and password are specified, the proxy will use the supplied token service uri to request a token.  If this value is left blank, the proxy will request a token URL from the ArcGIS server.
    * **domain**: The Windows domain to use with username/password when using Windows Authentication. Only applies to DotNet proxy.
    * **clientId**.  Used with clientSecret for OAuth authentication to obtain a token - if needed for OAuth 2.0 authentication. **NOTE**: If used to access hosted services, the service(s) must be owned by the user accessing it, (with the exception of credit-based esri services, e.g. routing, geoenrichment, etc.)
    * **clientSecret**: Used with clientId for OAuth authentication to obtain a token - if needed for OAuth 2.0 authentication.
    * **oauth2Endpoint**: When using OAuth 2.0 authentication specify the portal specific OAuth 2.0 authentication endpoint. The default value is https://www.arcgis.com/sharing/oauth2/.
    * **accessToken**: OAuth2 access token to use instead of on-demand access-token generation using clientId & clientSecret. Only applies to DotNet proxy.
    * **rateLimit**: The maximum number of requests with a particular referer over the specified **rateLimitPeriod**.
    * **rateLimitPeriod**: The time period (in minutes) within which the specified number of requests (rate_limit) sent with a particular referer will be tracked. The default value is 60 (one hour).
    * **hostRedirect**: The real URL to use instead of the "alias" one provided in the `url` property and that should be redirected. Example: `<serverUrl url="http://fakedomain" hostRedirect="http://172.16.85.2"/>`.

Note: Refresh the proxy application after updates to the proxy.config have been made.

Example of proxy to a WMS using HTTP Basic Authentication and rewriting the OnlineResource in GetCapabilites XML, and using a token
to access it. **Replace the _url_, _key_, _username_ and _password_ with your own values**:
```xml
<serverUrl url="https://url.lantmateriet.se/topowebb/wms/v1"
    key="MyMadeUpStringOfCharacters"
    username="user0001"
    password="xxXXxxXXxx"
    wmsResourceRewrite="true"
    matchAll="true"
    httpBasicAuth="true"
    changeEncodingToUTF8="true"
    >
</serverUrl>
```
The URL to add in ArcGIS Online for the above service will be:
```
https://[yourmachine]/proxy/MyMadeUpStringOfCharacters
```

Example of a tag for a resource which does not require authentication
```xml
<serverUrl url="http://sampleserver6.arcgisonline.com/arcgis/rest/services"
    matchAll="true">
</serverUrl>
```

## Folders and Files

The proxy consists of the following files:
* proxy.config: This file contains the [configuration settings for the proxy](README.md#proxy-configuration-settings). This is where you will define all the resources that will use the proxy. After updating this file you might need to refresh the proxy application using IIS tools in order for the changes to take effect.  **Important note:** In order to keep your credentials safe, ensure that your web server will not display the text inside your proxy.config in the browser (ie: http://[yourmachine]/proxy/proxy.config).
* proxy.ashx: The actual proxy application. In most cases you will not need to modify this file.
* proxy.xsd: a schema file for easier editing of proxy.config in Visual Studio.
* Web.config: An XML file that stores ASP.NET configuration data.
NOTE: as of v1.1.0, log levels and log file locations are specified in proxy config. By default the proxy will write log messages to a file named auth_proxy.log located in  'C:\Temp\Shared\proxy_logs'. Note that the folder location needs to exist in order for the log file to be successfully created.

## Requirements

* ASP.NET 4.0 or greater (4.5 is required on Windows 8/Server 2012, see [this article] (http://www.iis.net/learn/get-started/whats-new-in-iis-8/iis-80-using-aspnet-35-and-aspnet-45) for more information)

## Issues

Found a bug or want to request a new feature? Let us know by submitting an issue.

## Contributing

All contributions are welcome.

## Alternatives
This proxy is probably not the only way to solve access issue from Portal and ArcGIS Online.
We haven't tested other alternatives, but perhaps [MapProxy](https://mapproxy.org/) can be used?

## Licensing

Copyright 2014 Esri

Licensed under the Apache License, Version 2.0 (the "License");
You may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for specific language governing permissions and limitations under the license.
