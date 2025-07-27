/*
 * Android Network Monitor - HTTP/HTTPS Traffic Analysis
 * Purpose: Monitor network communications, API calls, and data transmission
 * Useful for: API analysis, data leakage detection, authentication flow analysis
 */

console.log("[*] Android Network Monitor loaded");

Java.perform(function() {
    
    // Monitor HttpURLConnection
    try {
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        
        // Hook connect method
        HttpURLConnection.connect.implementation = function() {
            var url = this.getURL().toString();
            var method = this.getRequestMethod();
            
            console.log("[*] HttpURLConnection.connect()");
            console.log("    URL: " + url);
            console.log("    Method: " + method);
            
            // Check for HTTP (insecure)
            if (url.startsWith("http://")) {
                console.log("[!] INSECURE HTTP CONNECTION DETECTED: " + url);
            }
            
            return this.connect();
        };

        // Hook getInputStream for response monitoring
        HttpURLConnection.getInputStream.implementation = function() {
            console.log("[*] HttpURLConnection.getInputStream() - Reading response");
            console.log("    Response code: " + this.getResponseCode());
            console.log("    Content type: " + this.getContentType());
            
            return this.getInputStream();
        };
        
        console.log("[+] HttpURLConnection hooks installed");
    } catch (e) {
        console.log("[-] HttpURLConnection hook failed: " + e);
    }

    // Monitor OkHttp3 (popular HTTP client)
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var Request = Java.use("okhttp3.Request");
        
        // Hook newCall method
        OkHttpClient.newCall.implementation = function(request) {
            console.log("[*] OkHttpClient.newCall()");
            console.log("    URL: " + request.url().toString());
            console.log("    Method: " + request.method());
            
            // Log headers
            var headers = request.headers();
            var headerNames = headers.names();
            var headerIterator = headerNames.iterator();
            
            console.log("    Headers:");
            while (headerIterator.hasNext()) {
                var headerName = headerIterator.next();
                var headerValue = headers.get(headerName);
                console.log("      " + headerName + ": " + headerValue);
                
                // Check for sensitive headers
                if (headerName.toLowerCase().includes("authorization") || 
                    headerName.toLowerCase().includes("token") ||
                    headerName.toLowerCase().includes("key")) {
                    console.log("[!] SENSITIVE HEADER DETECTED: " + headerName);
                }
            }
            
            return this.newCall(request);
        };
        
        console.log("[+] OkHttpClient hooks installed");
    } catch (e) {
        console.log("[-] OkHttpClient hook failed: " + e);
    }

    // Monitor Volley requests
    try {
        var Request = Java.use("com.android.volley.Request");
        
        Request.getUrl.implementation = function() {
            var url = this.getUrl();
            console.log("[*] Volley Request URL: " + url);
            
            if (url.startsWith("http://")) {
                console.log("[!] INSECURE VOLLEY REQUEST: " + url);
            }
            
            return url;
        };
        
        console.log("[+] Volley Request hooks installed");
    } catch (e) {
        console.log("[-] Volley Request hook failed: " + e);
    }

    // Monitor Retrofit (if present)
    try {
        var Retrofit = Java.use("retrofit2.Retrofit");
        
        // This is tricky since Retrofit uses dynamic proxies
        // We'll hook the baseUrl method instead
        Retrofit.baseUrl.implementation = function() {
            var baseUrl = this.baseUrl();
            console.log("[*] Retrofit base URL: " + baseUrl.toString());
            
            return baseUrl;
        };
        
        console.log("[+] Retrofit hooks installed");
    } catch (e) {
        console.log("[-] Retrofit hook failed: " + e);
    }

    // Monitor Socket connections
    try {
        var Socket = Java.use("java.net.Socket");
        
        Socket.connect.overload("java.net.SocketAddress").implementation = function(endpoint) {
            console.log("[*] Socket.connect()");
            console.log("    Endpoint: " + endpoint.toString());
            
            return this.connect(endpoint);
        };

        Socket.connect.overload("java.net.SocketAddress", "int").implementation = function(endpoint, timeout) {
            console.log("[*] Socket.connect() with timeout");
            console.log("    Endpoint: " + endpoint.toString());
            console.log("    Timeout: " + timeout + "ms");
            
            return this.connect(endpoint, timeout);
        };
        
        console.log("[+] Socket hooks installed");
    } catch (e) {
        console.log("[-] Socket hook failed: " + e);
    }

    // Monitor URL class usage
    try {
        var URL = Java.use("java.net.URL");
        
        URL.$init.overload("java.lang.String").implementation = function(spec) {
            console.log("[*] URL created: " + spec);
            
            if (spec.startsWith("http://")) {
                console.log("[!] INSECURE URL DETECTED: " + spec);
            }
            
            return this.$init(spec);
        };
        
        console.log("[+] URL hooks installed");
    } catch (e) {
        console.log("[-] URL hook failed: " + e);
    }

    // Monitor DNS lookups
    try {
        var InetAddress = Java.use("java.net.InetAddress");
        
        InetAddress.getByName.implementation = function(host) {
            console.log("[*] DNS lookup for: " + host);
            
            var result = this.getByName(host);
            console.log("    Resolved to: " + result.getHostAddress());
            
            return result;
        };

        InetAddress.getAllByName.implementation = function(host) {
            console.log("[*] DNS lookup (all) for: " + host);
            
            var results = this.getAllByName(host);
            for (var i = 0; i < results.length; i++) {
                console.log("    Resolved to: " + results[i].getHostAddress());
            }
            
            return results;
        };
        
        console.log("[+] InetAddress hooks installed");
    } catch (e) {
        console.log("[-] InetAddress hook failed: " + e);
    }

    // Monitor WebView network activity
    try {
        var WebView = Java.use("android.webkit.WebView");
        
        WebView.loadUrl.overload("java.lang.String").implementation = function(url) {
            console.log("[*] WebView.loadUrl(): " + url);
            
            if (url.startsWith("http://")) {
                console.log("[!] INSECURE WEBVIEW URL: " + url);
            }
            
            return this.loadUrl(url);
        };

        WebView.loadUrl.overload("java.lang.String", "java.util.Map").implementation = function(url, additionalHttpHeaders) {
            console.log("[*] WebView.loadUrl() with headers: " + url);
            
            // Log additional headers
            if (additionalHttpHeaders) {
                var keySet = additionalHttpHeaders.keySet();
                var iterator = keySet.iterator();
                
                console.log("    Additional headers:");
                while (iterator.hasNext()) {
                    var key = iterator.next();
                    var value = additionalHttpHeaders.get(key);
                    console.log("      " + key + ": " + value);
                }
            }
            
            return this.loadUrl(url, additionalHttpHeaders);
        };
        
        console.log("[+] WebView hooks installed");
    } catch (e) {
        console.log("[-] WebView hook failed: " + e);
    }

    // Monitor JSON data (often used in API calls)
    try {
        var JSONObject = Java.use("org.json.JSONObject");
        
        JSONObject.put.overload("java.lang.String", "java.lang.Object").implementation = function(name, value) {
            // Log sensitive-looking JSON keys
            var sensitiveKeys = ["password", "token", "secret", "key", "auth", "api_key", "access_token"];
            var lowerName = name.toLowerCase();
            
            sensitiveKeys.forEach(function(sensitiveKey) {
                if (lowerName.includes(sensitiveKey)) {
                    console.log("[!] SENSITIVE JSON KEY DETECTED: " + name + " = " + value);
                }
            });
            
            return this.put(name, value);
        };
        
        console.log("[+] JSONObject hooks installed");
    } catch (e) {
        console.log("[-] JSONObject hook failed: " + e);
    }

    // Monitor HTTP response reading
    try {
        var BufferedReader = Java.use("java.io.BufferedReader");
        
        var originalReadLine = BufferedReader.readLine;
        BufferedReader.readLine.implementation = function() {
            var line = originalReadLine.call(this);
            
            if (line != null && line.length > 0) {
                // Look for sensitive data patterns in responses
                var sensitivePatterns = [
                    /token["\s]*[:=]["\s]*([a-zA-Z0-9_-]+)/gi,
                    /key["\s]*[:=]["\s]*([a-zA-Z0-9_-]+)/gi,
                    /password["\s]*[:=]["\s]*([^"]+)/gi,
                    /secret["\s]*[:=]["\s]*([a-zA-Z0-9_-]+)/gi
                ];
                
                sensitivePatterns.forEach(function(pattern) {
                    var matches = line.match(pattern);
                    if (matches) {
                        console.log("[!] SENSITIVE DATA IN RESPONSE: " + matches[0]);
                    }
                });
            }
            
            return line;
        };
        
        console.log("[+] BufferedReader hooks installed");
    } catch (e) {
        console.log("[-] BufferedReader hook failed: " + e);
    }

    console.log("[*] Android Network Monitor setup complete!");
});