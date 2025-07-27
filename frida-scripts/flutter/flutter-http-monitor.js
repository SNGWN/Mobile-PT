/**
 * Flutter HTTP Traffic Monitor
 * Author: Mobile-PT Toolkit
 * Description: Monitors HTTP/HTTPS traffic in Flutter applications including Dio, http package, and native requests
 * Usage: frida -U -l flutter-http-monitor.js <package_name>
 */

setTimeout(function() {
    console.log("[*] Starting Flutter HTTP Traffic Monitor...");
    
    if (Java.available) {
        Java.perform(function() {
            console.log("[*] Monitoring Flutter HTTP traffic on Android");
            
            // ==============================================
            // OkHttp3 Monitoring (Common in Flutter)
            // ==============================================
            
            try {
                var OkHttpClient = Java.use("okhttp3.OkHttpClient");
                var Request = Java.use("okhttp3.Request");
                
                // Hook newCall method
                OkHttpClient.newCall.overload("okhttp3.Request").implementation = function(request) {
                    console.log("\n[*] ===== OKHTTP REQUEST =====");
                    console.log("[*] URL: " + request.url().toString());
                    console.log("[*] Method: " + request.method());
                    
                    // Log headers
                    var headers = request.headers();
                    console.log("[*] Headers:");
                    for (var i = 0; i < headers.size(); i++) {
                        var headerName = headers.name(i);
                        var headerValue = headers.value(i);
                        console.log("    " + headerName + ": " + headerValue);
                        
                        // Check for sensitive headers
                        if (headerName.toLowerCase().includes("authorization") || 
                            headerName.toLowerCase().includes("token") ||
                            headerName.toLowerCase().includes("api-key")) {
                            console.log("[!] SENSITIVE HEADER DETECTED: " + headerName);
                        }
                    }
                    
                    // Log request body if present
                    var body = request.body();
                    if (body) {
                        try {
                            var buffer = Java.use("okio.Buffer").$new();
                            var clonedBody = body; // Preserve the original body
                            try {
                                clonedBody.writeTo(buffer);
                                var bodyContent = buffer.readUtf8();
                                console.log("[*] Request Body: " + bodyContent);
                            } catch (e) {
                                console.log("[*] Request Body: <binary data>");
                            }
                            
                            // Check for sensitive data in body
                            var bodyLower = bodyContent.toLowerCase();
                            if (bodyLower.includes("password") || bodyLower.includes("token") || 
                                bodyLower.includes("secret") || bodyLower.includes("credential")) {
                                console.log("[!] SENSITIVE DATA in request body!");
                            }
                        } catch (e) {
                            console.log("[*] Request Body: <binary data>");
                        }
                    }
                    
                    console.log("[*] ===========================\n");
                    
                    var call = this.newCall(request);
                    
                    // Hook the response
                    try {
                        var Response = Java.use("okhttp3.Response");
                        var originalExecute = call.execute;
                        call.execute.implementation = function() {
                            var response = originalExecute.call(this);
                            
                            console.log("\n[*] ===== OKHTTP RESPONSE =====");
                            console.log("[*] Status Code: " + response.code());
                            console.log("[*] Message: " + response.message());
                            
                            // Log response headers
                            var responseHeaders = response.headers();
                            console.log("[*] Response Headers:");
                            for (var i = 0; i < responseHeaders.size(); i++) {
                                console.log("    " + responseHeaders.name(i) + ": " + responseHeaders.value(i));
                            }
                            
                            // Try to log response body
                            try {
                                var responseBody = response.body();
                                if (responseBody) {
                                    var responseContent = responseBody.string();
                                    console.log("[*] Response Body: " + responseContent);
                                    
                                    // Check for sensitive data in response
                                    var responseLower = responseContent.toLowerCase();
                                    if (responseLower.includes("password") || responseLower.includes("token") || 
                                        responseLower.includes("secret") || responseLower.includes("api_key")) {
                                        console.log("[!] SENSITIVE DATA in response body!");
                                    }
                                }
                            } catch (e) {
                                console.log("[*] Response Body: <couldn't read>");
                            }
                            
                            console.log("[*] ============================\n");
                            
                            return response;
                        };
                    } catch (e) {
                        console.log("[!] Response hooking failed: " + e);
                    }
                    
                    return call;
                };
                
                console.log("[✓] OkHttp monitoring enabled");
            } catch (e) {
                console.log("[!] OkHttp hook failed: " + e);
            }

            // ==============================================
            // HttpURLConnection Monitoring
            // ==============================================
            
            try {
                var HttpURLConnection = Java.use("java.net.HttpURLConnection");
                var URL = Java.use("java.net.URL");
                
                // Hook connect method
                HttpURLConnection.connect.implementation = function() {
                    console.log("\n[*] ===== HTTP URL CONNECTION =====");
                    console.log("[*] URL: " + this.getURL().toString());
                    console.log("[*] Method: " + this.getRequestMethod());
                    
                    // Log request properties
                    var requestProperties = this.getRequestProperties();
                    if (requestProperties && requestProperties.size() > 0) {
                        console.log("[*] Request Headers:");
                        var keySet = requestProperties.keySet();
                        var iterator = keySet.iterator();
                        while (iterator.hasNext()) {
                            var key = iterator.next();
                            var values = requestProperties.get(key);
                            console.log("    " + key + ": " + values.toString());
                        }
                    }
                    
                    console.log("[*] =================================\n");
                    
                    return this.connect();
                };
                
                // Hook getInputStream to monitor responses
                HttpURLConnection.getInputStream.implementation = function() {
                    console.log("[*] HTTP Response received for: " + this.getURL().toString());
                    console.log("[*] Response Code: " + this.getResponseCode());
                    console.log("[*] Response Message: " + this.getResponseMessage());
                    
                    return this.getInputStream();
                };
                
                console.log("[✓] HttpURLConnection monitoring enabled");
            } catch (e) {
                console.log("[!] HttpURLConnection hook failed: " + e);
            }

            // ==============================================
            // Platform Channel HTTP Monitoring
            // ==============================================
            
            try {
                var MethodChannel = Java.use("io.flutter.plugin.common.MethodChannel");
                var originalInvokeMethod = MethodChannel.invokeMethod.overload("java.lang.String", "java.lang.Object");
                
                originalInvokeMethod.implementation = function(method, arguments) {
                    // Monitor HTTP-related platform channel calls
                    if (method && (method.includes("http") || method.includes("request") || method.includes("download") || method.includes("upload"))) {
                        console.log("\n[*] ===== PLATFORM CHANNEL HTTP =====");
                        console.log("[*] Channel: " + this.name.value);
                        console.log("[*] Method: " + method);
                        
                        if (arguments) {
                            try {
                                console.log("[*] Arguments: " + JSON.stringify(arguments));
                            } catch (e) {
                                console.log("[*] Arguments: " + arguments.toString());
                            }
                        }
                        
                        console.log("[*] ==================================\n");
                    }
                    
                    return originalInvokeMethod.call(this, method, arguments);
                };
                
                console.log("[✓] Platform channel HTTP monitoring enabled");
            } catch (e) {
                console.log("[!] Platform channel HTTP hook failed: " + e);
            }

            // ==============================================
            // Socket Connection Monitoring
            // ==============================================
            
            try {
                var Socket = Java.use("java.net.Socket");
                
                // Hook socket connection
                Socket.$init.overload("java.lang.String", "int").implementation = function(host, port) {
                    console.log("[*] Socket connection to: " + host + ":" + port);
                    
                    // Check for common ports
                    if (port == 80) {
                        console.log("[!] HTTP connection detected!");
                    } else if (port == 443) {
                        console.log("[!] HTTPS connection detected!");
                    } else if (port == 8080 || port == 8443) {
                        console.log("[!] Proxy or alternative HTTP port detected!");
                    }
                    
                    return this.$init(host, port);
                };
                
                console.log("[✓] Socket monitoring enabled");
            } catch (e) {
                console.log("[!] Socket hook failed: " + e);
            }

            // ==============================================
            // WebSocket Monitoring
            // ==============================================
            
            try {
                // Look for WebSocket implementations
                Java.enumerateLoadedClasses({
                    onMatch: function(className) {
                        if (className.toLowerCase().includes("websocket")) {
                            console.log("[*] Found WebSocket class: " + className);
                            
                            try {
                                var WebSocketClass = Java.use(className);
                                console.log("[*] WebSocket class loaded: " + className);
                                // Additional WebSocket monitoring can be added here
                            } catch (e) {
                                // Skip if can't hook
                            }
                        }
                    },
                    onComplete: function() {}
                });
                
                console.log("[✓] WebSocket enumeration completed");
            } catch (e) {
                console.log("[!] WebSocket monitoring failed: " + e);
            }

            // ==============================================
            // Dio HTTP Client Monitoring (Popular Flutter package)
            // ==============================================
            
            try {
                Java.enumerateLoadedClasses({
                    onMatch: function(className) {
                        if (className.includes("dio") && (className.includes("Dio") || className.includes("Http"))) {
                            console.log("[*] Found Dio HTTP class: " + className);
                            
                            try {
                                var DioClass = Java.use(className);
                                console.log("[*] Monitoring Dio class: " + className);
                                
                                // Hook common Dio methods if they exist
                                var methods = DioClass.class.getDeclaredMethods();
                                for (var i = 0; i < methods.length; i++) {
                                    var methodName = methods[i].getName();
                                    if (methodName.includes("request") || methodName.includes("get") || 
                                        methodName.includes("post") || methodName.includes("put") || 
                                        methodName.includes("delete")) {
                                        console.log("[*] Found Dio HTTP method: " + methodName);
                                    }
                                }
                            } catch (e) {
                                // Skip if can't hook
                            }
                        }
                    },
                    onComplete: function() {}
                });
                
                console.log("[✓] Dio monitoring setup completed");
            } catch (e) {
                console.log("[!] Dio monitoring failed: " + e);
            }

            // ==============================================
            // DNS Resolution Monitoring
            // ==============================================
            
            try {
                var InetAddress = Java.use("java.net.InetAddress");
                
                // Hook getAllByName
                InetAddress.getAllByName.implementation = function(host) {
                    console.log("[*] DNS lookup for: " + host);
                    
                    // Check for suspicious domains
                    var hostLower = host.toLowerCase();
                    if (hostLower.includes("api") || hostLower.includes("auth") || hostLower.includes("login")) {
                        console.log("[!] API/Auth related domain detected!");
                    }
                    
                    return this.getAllByName(host);
                };
                
                console.log("[✓] DNS monitoring enabled");
            } catch (e) {
                console.log("[!] DNS hook failed: " + e);
            }

            console.log("[*] Flutter HTTP Traffic Monitor setup completed!");
        });
    }
    
    // ==============================================
    // iOS HTTP Monitoring
    // ==============================================
    
    if (ObjC.available) {
        console.log("[*] Monitoring Flutter HTTP traffic on iOS");
        
        try {
            // Hook NSURLSession
            var NSURLSession = ObjC.classes.NSURLSession;
            if (NSURLSession) {
                var dataTaskWithRequest = NSURLSession['- dataTaskWithRequest:'];
                if (dataTaskWithRequest) {
                    Interceptor.attach(dataTaskWithRequest.implementation, {
                        onEnter: function(args) {
                            var request = new ObjC.Object(args[2]);
                            var url = request.URL();
                            var method = request.HTTPMethod();
                            
                            console.log("\n[*] ===== iOS NSURLSession =====");
                            console.log("[*] URL: " + url.toString());
                            console.log("[*] Method: " + method.toString());
                            
                            var headers = request.allHTTPHeaderFields();
                            if (headers) {
                                console.log("[*] Headers: " + headers.toString());
                            }
                            
                            console.log("[*] =============================\n");
                        }
                    });
                }
            }
            
            // Hook NSURLConnection (legacy)
            var NSURLConnection = ObjC.classes.NSURLConnection;
            if (NSURLConnection) {
                var sendSynchronousRequest = NSURLConnection['+ sendSynchronousRequest:returningResponse:error:'];
                if (sendSynchronousRequest) {
                    Interceptor.attach(sendSynchronousRequest.implementation, {
                        onEnter: function(args) {
                            var request = new ObjC.Object(args[2]);
                            console.log("[*] iOS NSURLConnection request: " + request.URL().toString());
                        }
                    });
                }
            }
            
            console.log("[✓] iOS HTTP monitoring enabled");
        } catch (e) {
            console.log("[!] iOS HTTP monitoring failed: " + e);
        }
    }
    
}, 1000);