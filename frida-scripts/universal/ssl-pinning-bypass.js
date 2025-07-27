/*
 * Universal SSL Pinning Bypass
 * Works on both Android and iOS
 * Bypasses most common SSL pinning implementations
 */

console.log("[*] Universal SSL Pinning Bypass loaded");

// Android SSL Pinning Bypass
if (Java.available) {
    console.log("[*] Android environment detected");
    
    Java.perform(function() {
        // OkHTTP3 Certificate Pinner bypass
        try {
            var CertificatePinner = Java.use("okhttp3.CertificatePinner");
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
                console.log("[*] OkHTTP3 Certificate Pinner bypassed for: " + hostname);
                return;
            };
            console.log("[+] OkHTTP3 Certificate Pinner hooked");
        } catch (e) {
            console.log("[-] OkHTTP3 Certificate Pinner not found");
        }

        // HttpsURLConnection bypass
        try {
            var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hostnameVerifier) {
                console.log("[*] HttpsURLConnection setDefaultHostnameVerifier bypass");
                var TrustAllHostnameVerifier = Java.use("org.apache.http.conn.ssl.AllowAllHostnameVerifier");
                return this.setDefaultHostnameVerifier(TrustAllHostnameVerifier.$new());
            };
            console.log("[+] HttpsURLConnection hooked");
        } catch (e) {
            console.log("[-] HttpsURLConnection not found");
        }

        // X509TrustManager bypass
        try {
            var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            var SSLContext = Java.use("javax.net.ssl.SSLContext");
            
            var TrustManager = Java.registerClass({
                name: 'dev.asd.test.TrustManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {
                        console.log("[*] X509TrustManager checkServerTrusted bypassed");
                    },
                    getAcceptedIssuers: function() {
                        return [];
                    }
                }
            });
            
            var trustManager = TrustManager.$new();
            var sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, [trustManager], null);
            
            console.log("[+] X509TrustManager bypass installed");
        } catch (e) {
            console.log("[-] X509TrustManager bypass failed: " + e);
        }

        // Volley bypass
        try {
            var HurlStack = Java.use("com.android.volley.toolbox.HurlStack");
            HurlStack.createConnection.implementation = function(url) {
                var connection = this.createConnection(url);
                if (connection.toString().includes("HttpsURLConnection")) {
                    console.log("[*] Volley HTTPS connection bypassed");
                    connection.setHostnameVerifier(Java.use("javax.net.ssl.HttpsURLConnection").getDefaultHostnameVerifier());
                }
                return connection;
            };
            console.log("[+] Volley bypass hooked");
        } catch (e) {
            console.log("[-] Volley not found");
        }
    });
}

// iOS SSL Pinning Bypass
if (ObjC.available) {
    console.log("[*] iOS environment detected");
    
    // NSURLSessionConfiguration bypass
    try {
        var NSURLSessionConfiguration = ObjC.classes.NSURLSessionConfiguration;
        var oldMethod = NSURLSessionConfiguration['- URLSessionDidReceiveChallenge:completionHandler:'];
        
        if (oldMethod) {
            Interceptor.attach(oldMethod.implementation, {
                onEnter: function(args) {
                    console.log("[*] NSURLSession challenge bypassed");
                    var completionHandler = new ObjC.Block(args[3]);
                    completionHandler(1, null); // NSURLSessionAuthChallengeUseCredential
                }
            });
            console.log("[+] NSURLSessionConfiguration hooked");
        }
    } catch (e) {
        console.log("[-] NSURLSessionConfiguration bypass failed: " + e);
    }

    // SecTrustEvaluate bypass
    try {
        var SecTrustEvaluate = Module.findExportByName("Security", "SecTrustEvaluate");
        if (SecTrustEvaluate) {
            Interceptor.attach(SecTrustEvaluate, {
                onLeave: function(retval) {
                    console.log("[*] SecTrustEvaluate result modified");
                    retval.replace(0); // errSecSuccess
                }
            });
            console.log("[+] SecTrustEvaluate hooked");
        }
    } catch (e) {
        console.log("[-] SecTrustEvaluate bypass failed: " + e);
    }

    // tls_helper_create_peer_trust bypass
    try {
        var tls_helper_create_peer_trust = Module.findExportByName("libnetwork.dylib", "tls_helper_create_peer_trust");
        if (tls_helper_create_peer_trust) {
            Interceptor.attach(tls_helper_create_peer_trust, {
                onLeave: function(retval) {
                    console.log("[*] tls_helper_create_peer_trust bypassed");
                    retval.replace(0);
                }
            });
            console.log("[+] tls_helper_create_peer_trust hooked");
        }
    } catch (e) {
        console.log("[-] tls_helper_create_peer_trust not found");
    }
}

console.log("[*] Universal SSL Pinning Bypass setup complete!");