/**
 * Flutter SSL Certificate Pinning Bypass
 * Author: Mobile-PT Toolkit
 * Description: Comprehensive SSL pinning bypass for Flutter applications
 * Usage: frida -U -l flutter-ssl-pinning-bypass.js <package_name>
 */

setTimeout(function() {
    console.log("[*] Starting Flutter SSL Certificate Pinning Bypass...");
    
    if (Java.available) {
        Java.perform(function() {
            console.log("[*] Java runtime detected - Starting Android SSL bypass");
            
            // ==============================================
            // Standard Android SSL Bypass (for Flutter native code)
            // ==============================================
            
            try {
                // Hook X509TrustManager
                var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
                var TrustManager = Java.array("javax.net.ssl.TrustManager", [
                    Java.registerClass({
                        name: "com.flutter.bypass.CustomTrustManager",
                        implements: [X509TrustManager],
                        methods: {
                            checkClientTrusted: function(chain, authType) {
                                console.log("[*] checkClientTrusted - bypassed");
                            },
                            checkServerTrusted: function(chain, authType) {
                                console.log("[*] checkServerTrusted - bypassed");
                            },
                            getAcceptedIssuers: function() {
                                return Java.array("java.security.cert.X509Certificate", []);
                            }
                        }
                    }).$new()
                ]);

                // Hook SSLContext.init
                var SSLContext = Java.use("javax.net.ssl.SSLContext");
                SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function(keyManagers, trustManagers, secureRandom) {
                    console.log("[*] SSLContext.init() - bypassed with custom trust manager");
                    this.init(keyManagers, TrustManager, secureRandom);
                };

                console.log("[✓] Standard SSL hooks installed");
            } catch (e) {
                console.log("[!] Standard SSL bypass failed: " + e);
            }

            // ==============================================
            // OkHttp3 Certificate Pinning Bypass (Common in Flutter)
            // ==============================================
            
            try {
                var CertificatePinner = Java.use("okhttp3.CertificatePinner");
                CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function(hostname, peerCertificates) {
                    console.log("[*] OkHttp Certificate pinning bypassed for: " + hostname);
                    return;
                };
                
                CertificatePinner.check.overload("java.lang.String", "[Ljava.security.cert.Certificate;").implementation = function(hostname, peerCertificates) {
                    console.log("[*] OkHttp Certificate pinning bypassed for: " + hostname);
                    return;
                };
                
                console.log("[✓] OkHttp certificate pinning bypass installed");
            } catch (e) {
                console.log("[!] OkHttp certificate pinner not found: " + e);
            }

            // ==============================================
            // Flutter-Specific SSL Bypass
            // ==============================================
            
            try {
                // Hook Flutter engine native calls
                var FlutterJNI = Java.use("io.flutter.embedding.engine.FlutterJNI");
                
                // Hook platform message calls that might handle SSL
                var originalPlatformMessage = FlutterJNI.nativePlatformMessage;
                FlutterJNI.nativePlatformMessage.implementation = function(channel, message, responseId) {
                    if (channel && (channel.includes("http") || channel.includes("ssl") || channel.includes("certificate"))) {
                        console.log("[*] Flutter platform message (SSL-related): " + channel);
                    }
                    return originalPlatformMessage.call(this, channel, message, responseId);
                };
                
                console.log("[✓] Flutter engine hooks installed");
            } catch (e) {
                console.log("[!] Flutter engine hook failed: " + e);
            }

            // ==============================================
            // Method Channel SSL Bypass (Dart to Native communication)
            // ==============================================
            
            try {
                var MethodChannel = Java.use("io.flutter.plugin.common.MethodChannel");
                var originalInvokeMethod = MethodChannel.invokeMethod.overload("java.lang.String", "java.lang.Object");
                
                originalInvokeMethod.implementation = function(method, arguments) {
                    // Log SSL/HTTP related method calls
                    if (method && (method.includes("http") || method.includes("ssl") || method.includes("certificate") || method.includes("pinning"))) {
                        console.log("[*] Method channel SSL call: " + method);
                        console.log("[*] Arguments: " + JSON.stringify(arguments));
                        
                        // Bypass certificate validation methods
                        if (method.includes("validate") || method.includes("verify") || method.includes("check")) {
                            if (ENABLE_SSL_BYPASS) {
                                console.log("[*] Bypassing certificate validation method: " + method);
                                return Java.use("java.lang.Boolean").TRUE;
                            } else {
                                console.log("[!] SSL bypass attempted but is disabled. Method: " + method);
                            }
                        }
                    }
                    
                    return originalInvokeMethod.call(this, method, arguments);
                };
                
                console.log("[✓] Method channel hooks installed");
            } catch (e) {
                console.log("[!] Method channel hook failed: " + e);
            }

            // ==============================================
            // HttpURLConnection Bypass (used by some Flutter HTTP plugins)
            // ==============================================
            
            try {
                var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
                
                // Bypass hostname verification
                HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hostnameVerifier) {
                    console.log("[*] HttpsURLConnection hostname verifier bypassed");
                    var allHostsValid = Java.registerClass({
                        name: "com.flutter.bypass.HostnameVerifier",
                        implements: [Java.use("javax.net.ssl.HostnameVerifier")],
                        methods: {
                            verify: function(hostname, session) {
                                console.log("[*] Hostname verification bypassed for: " + hostname);
                                return true;
                            }
                        }
                    });
                    this.setDefaultHostnameVerifier(allHostsValid.$new());
                };
                
                // Bypass SSL socket factory
                HttpsURLConnection.setDefaultSSLSocketFactory.implementation = function(sslSocketFactory) {
                    console.log("[*] HttpsURLConnection SSL socket factory bypassed");
                    this.setDefaultSSLSocketFactory(sslSocketFactory);
                };
                
                console.log("[✓] HttpsURLConnection hooks installed");
            } catch (e) {
                console.log("[!] HttpsURLConnection hook failed: " + e);
            }

            // ==============================================
            // Dio HTTP Client Bypass (Popular Flutter HTTP package)
            // ==============================================
            
            try {
                // Look for Dio-related classes
                Java.enumerateLoadedClasses({
                    onMatch: function(className) {
                        if (className.includes("dio") || className.includes("Dio")) {
                            console.log("[*] Found Dio-related class: " + className);
                            
                            try {
                                var DioClass = Java.use(className);
                                console.log("[*] Hooking Dio class: " + className);
                                // Additional Dio-specific hooks can be added here
                            } catch (e) {
                                // Skip if class can't be hooked
                            }
                        }
                    },
                    onComplete: function() {}
                });
            } catch (e) {
                console.log("[!] Dio enumeration failed: " + e);
            }

            // ==============================================
            // Generic Certificate Validation Bypass
            // ==============================================
            
            try {
                // Hook all certificate-related methods
                var X509Certificate = Java.use("java.security.cert.X509Certificate");
                var CertificateFactory = Java.use("java.security.cert.CertificateFactory");
                
                // Bypass certificate verification
                X509Certificate.verify.overload("java.security.PublicKey").implementation = function(key) {
                    console.log("[*] X509Certificate.verify() bypassed");
                    return;
                };
                
                X509Certificate.verify.overload("java.security.PublicKey", "java.lang.String").implementation = function(key, sigProvider) {
                    console.log("[*] X509Certificate.verify() with provider bypassed");
                    return;
                };
                
                console.log("[✓] Generic certificate validation hooks installed");
            } catch (e) {
                console.log("[!] Generic certificate hooks failed: " + e);
            }

            console.log("[*] Flutter SSL Certificate Pinning Bypass completed!");
        });
    }
    
    // ==============================================
    // iOS/Native SSL Bypass (for iOS Flutter apps)
    // ==============================================
    
    if (ObjC.available) {
        console.log("[*] Objective-C runtime detected - Starting iOS SSL bypass");
        
        try {
            // Hook NSURLSession certificate validation
            var NSURLSession = ObjC.classes.NSURLSession;
            if (NSURLSession) {
                var originalDidReceiveChallenge = NSURLSession['- URLSession:didReceiveChallenge:completionHandler:'];
                if (originalDidReceiveChallenge) {
                    Interceptor.attach(originalDidReceiveChallenge.implementation, {
                        onEnter: function(args) {
                            console.log("[*] NSURLSession certificate challenge bypassed");
                            var completionHandler = new ObjC.Block(args[4]);
                            completionHandler(1, null); // NSURLSessionAuthChallengeUseCredential = 1
                        }
                    });
                }
            }

            // Hook NSURLConnection (legacy)
            var NSURLConnection = ObjC.classes.NSURLConnection;
            if (NSURLConnection) {
                var canAuthenticateAgainstProtectionSpace = NSURLConnection['+ canAuthenticateAgainstProtectionSpace:'];
                if (canAuthenticateAgainstProtectionSpace) {
                    Interceptor.attach(canAuthenticateAgainstProtectionSpace.implementation, {
                        onLeave: function(retval) {
                            console.log("[*] NSURLConnection auth bypassed");
                            retval.replace(1);
                        }
                    });
                }
            }

            console.log("[✓] iOS SSL bypass hooks installed");
        } catch (e) {
            console.log("[!] iOS SSL bypass failed: " + e);
        }
    }
    
}, 1000);