# Flutter Application Security Testing Guide

## Table of Contents
1. [Flutter Architecture Overview](#flutter-architecture-overview)
2. [Flutter Security Model](#flutter-security-model)
3. [Testing Environment Setup](#testing-environment-setup)
4. [Static Analysis](#static-analysis)
5. [Dynamic Analysis](#dynamic-analysis)
6. [Network Traffic Interception](#network-traffic-interception)
7. [Certificate Pinning Bypass](#certificate-pinning-bypass)
8. [Common Vulnerabilities](#common-vulnerabilities)
9. [Testing Tools](#testing-tools)
10. [FRIDA Scripts for Flutter](#frida-scripts-for-flutter)
11. [Best Practices](#best-practices)

## Flutter Architecture Overview

### Flutter Framework Structure
```
┌─────────────────────────────────────┐
│        Flutter Application         │
├─────────────────────────────────────┤
│         Dart Framework             │
├─────────────────────────────────────┤
│         Flutter Engine             │
├─────────────────────────────────────┤
│       Platform Embedder            │
├─────────────────────────────────────┤
│     Android/iOS Platform           │
└─────────────────────────────────────┘
```

### Key Components:
- **Dart VM**: Executes Dart code and manages application lifecycle
- **Flutter Engine**: C++ engine that provides low-level rendering support
- **Platform Embedder**: Platform-specific embedding layer
- **Framework**: High-level APIs written in Dart
- **Native Plugins**: Platform-specific code for accessing device features

### Flutter vs Native Apps:
- **Code Compilation**: Dart code compiled to native ARM/x64 machine code
- **UI Rendering**: Uses Skia graphics engine for custom rendering
- **Platform Channels**: Communication bridge between Dart and native platform
- **Bundle Structure**: Different from traditional Android/iOS apps

## Flutter Security Model

### Unique Security Characteristics:

#### 1. **Dart Code Compilation**
- Dart code compiled to native machine code
- No interpretation at runtime (in release mode)
- AOT (Ahead-of-Time) compilation for production apps
- JIT (Just-in-Time) compilation for development

#### 2. **Platform Channel Security**
- Communication between Dart and native platform
- Method calls serialized as JSON
- Potential for injection attacks
- Need to validate platform channel inputs

#### 3. **Asset Security**
- Flutter assets bundled with application
- No native resource protection
- Assets accessible via file system
- Potential for sensitive data exposure

#### 4. **Network Layer**
- Uses platform-native HTTP clients
- Inherits platform SSL/TLS implementations
- Custom certificate pinning implementations
- Different debugging approaches needed

## Testing Environment Setup

### Required Tools:
- **Flutter SDK** (latest stable version)
- **Android Studio/VS Code** with Flutter plugins
- **Android SDK** and **Xcode** (for respective platforms)
- **FRIDA** for dynamic instrumentation
- **Proxy tools** (Burp Suite, OWASP ZAP, mitmproxy)

### Flutter Development Environment:
```bash
# Install Flutter SDK
git clone https://github.com/flutter/flutter.git -b stable
export PATH="$PATH:`pwd`/flutter/bin"

# Verify installation
flutter doctor

# Install additional tools
flutter pub global activate flutterfire_cli
dart pub global activate dhttpd
```

### Device Setup for Testing:

#### Android Flutter App Testing:
```bash
# Enable Developer Options and USB Debugging
# Install app in debug mode
flutter run --debug

# Install app in release mode for production testing
flutter build apk --release
adb install build/app/outputs/flutter-apk/app-release.apk
```

#### iOS Flutter App Testing:
```bash
# Install app in debug mode
flutter run --debug

# Build for release testing
flutter build ios --release
```

## Static Analysis

### Flutter App Structure Analysis:

#### Android Flutter APK Structure:
```
app-release.apk
├── AndroidManifest.xml
├── classes.dex                    # Android-specific code
├── lib/
│   ├── arm64-v8a/
│   │   ├── libflutter.so         # Flutter engine
│   │   └── libapp.so             # Compiled Dart code
│   └── armeabi-v7a/
├── assets/
│   └── flutter_assets/           # Flutter assets and code
│       ├── fonts/
│       ├── packages/
│       ├── AssetManifest.json
│       ├── FontManifest.json
│       └── kernel_blob.bin       # Dart kernel snapshot
└── META-INF/
```

#### iOS Flutter App Structure:
```
Runner.app/
├── Runner                        # Main executable
├── Info.plist
├── Frameworks/
│   ├── Flutter.framework/        # Flutter engine
│   └── App.framework/           # Compiled Dart code
└── flutter_assets/              # Flutter assets
    ├── fonts/
    ├── packages/
    ├── AssetManifest.json
    └── kernel_blob.bin
```

### Static Analysis Tools:

#### 1. **Flutter Asset Analysis**
```bash
# Extract Flutter assets from APK
unzip app-release.apk
cd assets/flutter_assets/

# Analyze asset manifest
cat AssetManifest.json | jq '.'

# Look for sensitive files
find . -name "*.json" -o -name "*.txt" -o -name "*.config" | xargs grep -i "password\|secret\|api\|token"
```

#### 2. **Dart Snapshot Analysis**
```bash
# Extract Dart snapshot (limited analysis)
# Note: Dart AOT snapshots are mostly native code
objdump -d libapp.so | grep -A 10 -B 10 "string_literal"

# Search for strings in compiled Dart code
strings libapp.so | grep -i "http\|api\|secret\|password"
```

#### 3. **Reify Tool (Dart AOT Analysis)**
```bash
# Install Reify for Flutter reverse engineering
pip install reify

# Analyze Flutter app
reify app-release.apk

# Extract Dart code structure
reify --list-classes app-release.apk
```

## Dynamic Analysis

### Runtime Analysis Techniques:

#### 1. **Flutter Inspector**
```bash
# Launch app with Flutter Inspector
flutter run --debug
# Open DevTools in browser: http://localhost:9100
```

#### 2. **Dart VM Observatory**
```bash
# Enable VM service for debugging
flutter run --debug --enable-software-rendering

# Connect to Observatory
# URL displayed in flutter run output
```

#### 3. **Platform-Specific Debugging**
```bash
# Android debugging
adb logcat | grep flutter

# iOS debugging
# Use Xcode console or device console
```

### Memory Analysis:
```bash
# Dump Flutter app memory (Android)
adb shell dumpsys meminfo com.example.flutter_app

# Monitor memory usage
flutter run --profile
# Use Flutter Performance tab in DevTools
```

## Network Traffic Interception

### Challenges with Flutter Apps:
- **Custom HTTP Implementations**: May not respect system proxy settings
- **Certificate Pinning**: Often implemented at Dart level
- **Encrypted Communication**: End-to-end encryption common
- **Binary Protocol Usage**: gRPC and other binary protocols

### Proxy Configuration:

#### 1. **System Proxy Setup**
```bash
# Android device proxy configuration
adb shell settings put global http_proxy <proxy_ip>:<proxy_port>

# Alternative: WiFi proxy settings
# Settings > WiFi > Network > Advanced > Proxy
```

#### 2. **Flutter-Specific Proxy Configuration**
```dart
// Force app to use proxy in debug mode
import 'dart:io';

void main() {
  // Set proxy for debug builds
  if (kDebugMode) {
    HttpOverrides.global = ProxyHttpOverrides();
  }
  runApp(MyApp());
}

class ProxyHttpOverrides extends HttpOverrides {
  @override
  HttpClient createHttpClient(SecurityContext? context) {
    return super.createHttpClient(context)
      ..findProxy = (uri) {
        return 'PROXY 192.168.1.100:8080;';
      };
  }
}
```

#### 3. **Using Proxyman/Charles for Flutter**
```bash
# Install certificate in Android system store
adb push cert.pem /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/cert.pem

# For Android 7+ (Network Security Config)
# Add network_security_config.xml to bypass certificate pinning
```

### Advanced Interception Techniques:

#### 1. **FRIDA-based HTTP Interception**
```javascript
// Flutter HTTP interception script
Java.perform(function() {
    // Hook okhttp3 (commonly used in Flutter)
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    var Request = Java.use("okhttp3.Request");
    
    OkHttpClient.newCall.overload("okhttp3.Request").implementation = function(request) {
        console.log("[*] HTTP Request intercepted:");
        console.log("URL: " + request.url().toString());
        console.log("Method: " + request.method());
        
        // Log headers
        var headers = request.headers();
        for (var i = 0; i < headers.size(); i++) {
            console.log("Header: " + headers.name(i) + " = " + headers.value(i));
        }
        
        return this.newCall(request);
    };
});
```

#### 2. **mitmproxy for Flutter**
```python
# mitmproxy script for Flutter apps
from mitmproxy import http
import json

def request(flow: http.HTTPFlow) -> None:
    # Log Flutter app requests
    if "flutter" in flow.request.pretty_host.lower():
        print(f"Flutter Request: {flow.request.method} {flow.request.pretty_url}")
        
        # Log request body if JSON
        if flow.request.content:
            try:
                data = json.loads(flow.request.content)
                print(f"Request Body: {json.dumps(data, indent=2)}")
            except:
                print(f"Request Body (raw): {flow.request.content}")

def response(flow: http.HTTPFlow) -> None:
    # Log Flutter app responses
    if "flutter" in flow.request.pretty_host.lower():
        print(f"Flutter Response: {flow.response.status_code}")
        
        # Log response body if JSON
        if flow.response.content:
            try:
                data = json.loads(flow.response.content)
                print(f"Response Body: {json.dumps(data, indent=2)}")
            except:
                print(f"Response Body (raw): {flow.response.content}")
```

## Certificate Pinning Bypass

### Flutter Certificate Pinning Implementation:
```dart
// Common Flutter certificate pinning implementation
import 'dart:io';
import 'package:dio/dio.dart';

class PinnedCertificateInterceptor extends Interceptor {
  @override
  void onRequest(RequestOptions options, RequestInterceptorHandler handler) {
    // Custom certificate validation
    options.extra['pinned_cert'] = true;
    handler.next(options);
  }
}
```

### Bypass Techniques:

#### 1. **FRIDA-based Certificate Pinning Bypass**
```javascript
// Universal Flutter SSL pinning bypass
setTimeout(function() {
    Java.perform(function() {
        console.log("[*] Starting Flutter SSL pinning bypass");
        
        // Hook common SSL verification methods
        try {
            var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            var SSLContext = Java.use("javax.net.ssl.SSLContext");
            var TrustManager = Java.use("javax.net.ssl.TrustManager");
            
            // Create custom trust manager that accepts all certificates
            var TrustManagers = Java.array("javax.net.ssl.TrustManager", [
                Java.registerClass({
                    name: "com.example.CustomTrustManager",
                    implements: [X509TrustManager],
                    methods: {
                        checkClientTrusted: function(chain, authType) {
                            console.log("[*] checkClientTrusted bypassed");
                        },
                        checkServerTrusted: function(chain, authType) {
                            console.log("[*] checkServerTrusted bypassed");
                        },
                        getAcceptedIssuers: function() {
                            return Java.array("java.security.cert.X509Certificate", []);
                        }
                    }
                }).$new()
            ]);
            
            // Hook SSL context initialization
            SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function(keyManagers, trustManagers, secureRandom) {
                console.log("[*] SSLContext.init() bypassed");
                this.init(keyManagers, TrustManagers, secureRandom);
            };
            
        } catch (e) {
            console.log("[!] Error in SSL bypass: " + e);
        }
        
        // Hook OkHttp certificate pinner
        try {
            var CertificatePinner = Java.use("okhttp3.CertificatePinner");
            CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function(hostname, peerCertificates) {
                console.log("[*] Certificate pinning bypassed for: " + hostname);
                return;
            };
        } catch (e) {
            console.log("[!] OkHttp not found: " + e);
        }
        
        // Hook Dio (Flutter HTTP client) certificate validation
        try {
            var HttpClient = Java.use("java.net.HttpURLConnection");
            if (HttpClient) {
                HttpClient.getDefaultHostnameVerifier.implementation = function() {
                    console.log("[*] Default hostname verifier bypassed");
                    return Java.use("javax.net.ssl.HttpsURLConnection").getDefaultHostnameVerifier();
                };
            }
        } catch (e) {
            console.log("[!] HttpClient bypass failed: " + e);
        }
    });
}, 1000);
```

#### 2. **Custom Network Security Config (Android)**
```xml
<!-- res/xml/network_security_config.xml -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user"/>
            <certificates src="system"/>
        </trust-anchors>
    </debug-overrides>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="user"/>
            <certificates src="system"/>
        </trust-anchors>
    </base-config>
</network-security-config>
```

#### 3. **Flutter-Specific Bypass Script**
```javascript
// Flutter Dart-level SSL bypass
setTimeout(function() {
    if (Java.available) {
        Java.perform(function() {
            console.log("[*] Flutter SSL Pinning Bypass Started");
            
            // Hook Dart HTTP client (used by Flutter)
            try {
                var DartHttpClient = Java.use("dart.io.HttpClient");
                if (DartHttpClient) {
                    console.log("[*] Found Dart HttpClient");
                    // Additional Dart-specific hooks here
                }
            } catch (e) {
                console.log("[!] Dart HttpClient not accessible: " + e);
            }
            
            // Hook platform channels that might handle HTTP
            try {
                var MethodChannel = Java.use("io.flutter.plugin.common.MethodChannel");
                var originalInvokeMethod = MethodChannel.invokeMethod.overload("java.lang.String", "java.lang.Object");
                
                originalInvokeMethod.implementation = function(method, arguments) {
                    if (method.includes("http") || method.includes("network")) {
                        console.log("[*] Platform channel HTTP call: " + method);
                        console.log("[*] Arguments: " + JSON.stringify(arguments));
                    }
                    return originalInvokeMethod.call(this, method, arguments);
                };
            } catch (e) {
                console.log("[!] Platform channel hook failed: " + e);
            }
        });
    }
}, 2000);
```

## Common Vulnerabilities

### 1. **Insecure Data Storage**
- **Flutter Secure Storage Issues**: Improper use of flutter_secure_storage
- **Shared Preferences Exposure**: Sensitive data in plain text
- **Asset Bundle Exposure**: Sensitive files in flutter_assets

#### Testing:
```bash
# Extract and analyze Flutter assets
unzip app-release.apk
cd assets/flutter_assets/

# Look for configuration files
find . -name "*.json" -o -name "*.yaml" -o -name "*.config" | xargs cat | grep -i "password\|api\|secret\|token"

# Check Android shared preferences
adb shell run-as com.example.flutter_app
cat shared_prefs/*.xml | grep -i "sensitive\|password\|token"
```

### 2. **Platform Channel Vulnerabilities**
- **Injection Attacks**: Unsanitized input from Dart to native
- **Privilege Escalation**: Improper permission checks
- **Data Leakage**: Sensitive data in platform channel communication

#### Testing:
```javascript
// FRIDA script to monitor platform channels
Java.perform(function() {
    var MethodChannel = Java.use("io.flutter.plugin.common.MethodChannel");
    
    MethodChannel.invokeMethod.overload("java.lang.String", "java.lang.Object").implementation = function(method, arguments) {
        console.log("[*] Platform Channel Call:");
        console.log("Method: " + method);
        console.log("Arguments: " + JSON.stringify(arguments));
        
        var result = this.invokeMethod(method, arguments);
        console.log("Result: " + JSON.stringify(result));
        
        return result;
    };
});
```

### 3. **Network Security Issues**
- **Insufficient Transport Security**: Weak TLS configuration
- **Certificate Validation Bypass**: Improper SSL implementation
- **API Security**: Insecure API endpoints and authentication

#### Testing:
```bash
# Monitor network traffic during app usage
mitmproxy -s flutter_intercept.py --set confdir=~/.mitmproxy

# Test for weak TLS configurations
sslscan target.api.com
testssl.sh target.api.com
```

### 4. **Binary Protection Issues**
- **Debug Information**: Debug symbols in release builds
- **Code Obfuscation**: Lack of code obfuscation
- **Anti-Tampering**: Missing integrity checks

#### Testing:
```bash
# Check for debug information in Flutter engine
strings libflutter.so | grep -i debug
objdump -t libapp.so | grep -i debug

# Analyze Dart snapshot for symbols
nm libapp.so | grep -v " U " | head -20
```

## Testing Tools

### Flutter-Specific Tools:

#### 1. **Flutter Inspector**
```bash
# Launch app with inspector
flutter run --debug
# Open DevTools: http://localhost:9100
```

#### 2. **Reify (Flutter Reverse Engineering)**
```bash
# Install Reify
pip install reify

# Analyze Flutter app
reify app-release.apk

# Extract class information
reify --list-classes app-release.apk
reify --dump-class ClassName app-release.apk
```

#### 3. **reflutter (Flutter Reverse Engineering)**
```bash
# Install reflutter
git clone https://github.com/ptswarm/reflutter.git
cd reflutter
pip install -r requirements.txt

# Analyze Flutter app
python reflutter.py app-release.apk

# Extract Dart snapshot
python reflutter.py --extract-snapshot app-release.apk
```

### Network Analysis Tools:

#### 1. **HTTP Toolkit**
```bash
# Specialized tool for HTTP/HTTPS interception
# Good Flutter support with automatic certificate installation
# Download from: httptoolkit.tech
```

#### 2. **mitmproxy with Flutter Support**
```python
# flutter_addon.py for mitmproxy
from mitmproxy import http
import json

class FlutterAddon:
    def request(self, flow: http.HTTPFlow) -> None:
        if self.is_flutter_request(flow):
            self.log_flutter_request(flow)
    
    def response(self, flow: http.HTTPFlow) -> None:
        if self.is_flutter_request(flow):
            self.log_flutter_response(flow)
    
    def is_flutter_request(self, flow):
        # Detect Flutter requests by headers or patterns
        user_agent = flow.request.headers.get("user-agent", "")
        return "Dart/" in user_agent or "Flutter/" in user_agent
    
    def log_flutter_request(self, flow):
        print(f"[Flutter] {flow.request.method} {flow.request.pretty_url}")
        
    def log_flutter_response(self, flow):
        print(f"[Flutter] Response: {flow.response.status_code}")

addons = [FlutterAddon()]
```

## FRIDA Scripts for Flutter

### 1. **Flutter Method Hooking**
```javascript
// Flutter method interceptor
setTimeout(function() {
    Java.perform(function() {
        console.log("[*] Flutter Method Hooking Started");
        
        // Hook Flutter engine methods
        try {
            var FlutterJNI = Java.use("io.flutter.embedding.engine.FlutterJNI");
            
            FlutterJNI.nativePlatformMessage.implementation = function(channel, message, responseId) {
                console.log("[*] Platform Message:");
                console.log("Channel: " + channel);
                console.log("Message: " + Java.use("java.lang.String").$new(message));
                
                return this.nativePlatformMessage(channel, message, responseId);
            };
        } catch (e) {
            console.log("[!] FlutterJNI hook failed: " + e);
        }
        
        // Hook method channel handler
        try {
            var MethodCallHandler = Java.use("io.flutter.plugin.common.MethodChannel$MethodCallHandler");
            // Hook onMethodCall if available
        } catch (e) {
            console.log("[!] MethodCallHandler hook failed: " + e);
        }
    });
}, 1000);
```

### 2. **Flutter Crypto Monitoring**
```javascript
// Monitor cryptographic operations in Flutter apps
Java.perform(function() {
    console.log("[*] Flutter Crypto Monitor Started");
    
    // Hook common crypto libraries used by Flutter
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.getInstance.overload("java.lang.String").implementation = function(transformation) {
            console.log("[*] Cipher.getInstance: " + transformation);
            return this.getInstance(transformation);
        };
        
        Cipher.doFinal.overload("[B").implementation = function(input) {
            console.log("[*] Cipher.doFinal called");
            console.log("Input length: " + input.length);
            
            var result = this.doFinal(input);
            console.log("Output length: " + result.length);
            
            return result;
        };
    } catch (e) {
        console.log("[!] Cipher hook failed: " + e);
    }
    
    // Hook key generation
    try {
        var KeyGenerator = Java.use("javax.crypto.KeyGenerator");
        KeyGenerator.generateKey.implementation = function() {
            console.log("[*] Key generation detected");
            return this.generateKey();
        };
    } catch (e) {
        console.log("[!] KeyGenerator hook failed: " + e);
    }
});
```

### 3. **Flutter Storage Monitor**
```javascript
// Monitor Flutter storage operations
Java.perform(function() {
    console.log("[*] Flutter Storage Monitor Started");
    
    // Hook SharedPreferences (used by shared_preferences plugin)
    try {
        var SharedPreferences = Java.use("android.content.SharedPreferences");
        var Editor = Java.use("android.content.SharedPreferences$Editor");
        
        Editor.putString.implementation = function(key, value) {
            console.log("[*] SharedPreferences.putString:");
            console.log("Key: " + key);
            console.log("Value: " + value);
            
            return this.putString(key, value);
        };
        
        SharedPreferences.getString.implementation = function(key, defValue) {
            var result = this.getString(key, defValue);
            console.log("[*] SharedPreferences.getString:");
            console.log("Key: " + key);
            console.log("Value: " + result);
            
            return result;
        };
    } catch (e) {
        console.log("[!] SharedPreferences hook failed: " + e);
    }
    
    // Hook file operations
    try {
        var FileOutputStream = Java.use("java.io.FileOutputStream");
        FileOutputStream.$init.overload("java.lang.String").implementation = function(name) {
            console.log("[*] File write attempt: " + name);
            return this.$init(name);
        };
        
        var FileInputStream = Java.use("java.io.FileInputStream");
        FileInputStream.$init.overload("java.lang.String").implementation = function(name) {
            console.log("[*] File read attempt: " + name);
            return this.$init(name);
        };
    } catch (e) {
        console.log("[!] File operation hook failed: " + e);
    }
});
```

## Best Practices

### For Security Testers:

#### 1. **Flutter-Specific Testing Approach**
- Test both debug and release builds
- Analyze Flutter assets and snapshots
- Monitor platform channel communications
- Test network interception with multiple tools
- Validate both Dart and native code security

#### 2. **Tool Combination Strategy**
```bash
# Comprehensive Flutter testing workflow
# 1. Static analysis
reify app-release.apk
strings libapp.so | grep -i "api\|secret\|password"

# 2. Dynamic analysis
frida -U -l flutter_hooks.js com.example.flutter_app

# 3. Network testing
mitmproxy -s flutter_addon.py --set confdir=~/.mitmproxy

# 4. Binary analysis
objdump -d libapp.so | grep -A 5 -B 5 "bl.*http"
```

#### 3. **Common Pitfalls to Avoid**
- Don't rely only on traditional Android/iOS testing methods
- Flutter apps have different architectures than native apps
- Platform channels require special attention
- Network interception may need custom configuration

### For Developers:

#### 1. **Secure Development Practices**
```dart
// Secure HTTP client configuration
import 'package:dio/dio.dart';
import 'package:dio_certificate_pinning/dio_certificate_pinning.dart';

final dio = Dio();
dio.interceptors.add(
  CertificatePinningInterceptor(
    allowedSHAFingerprints: ['SHA256:XXXXXX...'],
  ),
);

// Secure storage implementation
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

const secureStorage = FlutterSecureStorage(
  aOptions: AndroidOptions(
    encryptedSharedPreferences: true,
  ),
  iOptions: IOSOptions(
    accessibility: IOSAccessibility.first_unlock_this_device,
  ),
);
```

#### 2. **Production Security Checklist**
- Enable code obfuscation: `flutter build apk --obfuscate --split-debug-info=debug-info/`
- Remove debug information from release builds
- Implement proper certificate pinning
- Validate all platform channel inputs
- Use secure storage for sensitive data
- Implement runtime application self-protection (RASP)

#### 3. **Security Testing Integration**
```yaml
# pubspec.yaml - Development dependencies for security testing
dev_dependencies:
  flutter_test:
    sdk: flutter
  integration_test:
    sdk: flutter
  # Add security testing tools
  mockito: ^5.0.0
  http_mock_adapter: ^0.3.0
```

---

For practical examples and ready-to-use scripts, check the Flutter-specific directories in this repository.

## References

- [IMQ Minded Security Blog: Bypassing Certificate Pinning on Flutter-based Android Apps](https://blog.imq.nl/bypassing-certificate-pinning-flutter-android-apps/)
- [Flutter and Proxy debugging techniques](https://medium.com/@sergey.yamshchikov/flutter-and-proxy-d9bf68c8c3d4)
- [Intercepting traffic from Android Flutter applications – NVISO Labs](https://blog.nviso.eu/2021/06/02/intercepting-traffic-from-android-flutter-applications/)
- [MASTG-TECH-0109: Intercepting Flutter HTTPS Traffic - OWASP Mobile Application Security](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0109/)
- [Flutter Security Best Practices](https://flutter.dev/docs/development/platform-integration/security)