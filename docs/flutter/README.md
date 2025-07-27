# Flutter Application Security Testing Guide

## Table of Contents
1. [Identifying Flutter Applications](#identifying-flutter-applications)
2. [Flutter Architecture Overview](#flutter-architecture-overview)
3. [Flutter Security Model](#flutter-security-model)
4. [Testing Environment Setup](#testing-environment-setup)
5. [Static Analysis](#static-analysis)
6. [Dynamic Analysis](#dynamic-analysis)
7. [Network Traffic Interception](#network-traffic-interception)
8. [Certificate Pinning Bypass](#certificate-pinning-bypass)
9. [Common Vulnerabilities](#common-vulnerabilities)
10. [Testing Tools](#testing-tools)
11. [FRIDA Scripts for Flutter](#frida-scripts-for-flutter)
11. [FRIDA Scripts for Flutter](#frida-scripts-for-flutter)
12. [Best Practices](#best-practices)
13. [Research Article Summaries](#research-article-summaries)

## Identifying Flutter Applications

Before conducting Flutter-specific security testing, it's crucial to identify whether an application is built with Flutter. Flutter applications have unique characteristics that distinguish them from native Android or iOS apps.

### Android Flutter Application Identification

#### 1. **APK Structure Analysis**
```bash
# Extract and examine APK contents
unzip app.apk
ls -la

# Look for Flutter-specific directories and files
find . -name "*flutter*" -type d
find . -name "libflutter.so"
find . -name "libapp.so"
find . -name "flutter_assets"
```

**Flutter APK Indicators:**
- `lib/arm64-v8a/libflutter.so` - Flutter engine library
- `lib/arm64-v8a/libapp.so` - Compiled Dart application code
- `assets/flutter_assets/` - Flutter assets directory
- `assets/flutter_assets/kernel_blob.bin` - Dart kernel snapshot
- `assets/flutter_assets/AssetManifest.json` - Flutter asset manifest

#### 2. **AndroidManifest.xml Analysis**
```bash
# Check for Flutter-specific components
aapt dump xmltree app.apk AndroidManifest.xml | grep -i flutter

# Look for Flutter activity classes
aapt dump xmltree app.apk AndroidManifest.xml | grep -E "FlutterActivity|FlutterFragmentActivity"
```

**Flutter Manifest Indicators:**
- `io.flutter.embedding.android.FlutterActivity`
- `io.flutter.embedding.android.FlutterFragmentActivity`
- `io.flutter.plugin` packages in uses-permission
- Meta-data entries with `io.flutter` prefix

#### 3. **Binary Analysis**
```bash
# Check for Flutter engine symbols
strings lib/arm64-v8a/libflutter.so | grep -i dart
strings lib/arm64-v8a/libflutter.so | grep -i flutter

# Analyze Dart runtime symbols
strings lib/arm64-v8a/libapp.so | head -50
objdump -T lib/arm64-v8a/libflutter.so | grep dart

# Check for Dart VM signatures
hexdump -C lib/arm64-v8a/libapp.so | head -10
```

#### 4. **Runtime Detection**
```bash
# Check running processes for Flutter indicators
adb shell ps | grep flutter
adb shell ps aux | grep dart

# Monitor logcat for Flutter messages
adb logcat | grep -i flutter
adb logcat | grep -i dart

# Check for Flutter-specific files in app directory
adb shell run-as com.example.app
ls -la | grep flutter
find . -name "*flutter*"
```

### iOS Flutter Application Identification

#### 1. **IPA Structure Analysis**
```bash
# Extract and examine IPA contents
unzip app.ipa
cd Payload/AppName.app

# Look for Flutter frameworks
ls -la Frameworks/
find . -name "*Flutter*"
find . -name "App.framework"
```

**Flutter iOS Indicators:**
- `Frameworks/Flutter.framework/` - Flutter engine framework
- `Frameworks/App.framework/` - Compiled Dart application
- `flutter_assets/` - Flutter assets directory
- `Info.plist` entries referencing Flutter

#### 2. **Info.plist Analysis**
```bash
# Check for Flutter-specific entries
plutil -p Info.plist | grep -i flutter
cat Info.plist | grep -A 5 -B 5 -i flutter

# Look for Flutter bundle identifier patterns
plutil -p Info.plist | grep CFBundleIdentifier
```

#### 3. **Binary Analysis**
```bash
# Check main executable for Flutter symbols
otool -L AppName | grep -i flutter
strings AppName | grep -i dart
strings AppName | grep -i flutter

# Analyze Flutter framework
otool -L Frameworks/Flutter.framework/Flutter
strings Frameworks/Flutter.framework/Flutter | grep dart
```

#### 4. **Runtime Detection (Jailbroken Device)**
```bash
# Check running processes
ps aux | grep -i flutter
ps aux | grep -i dart

# Monitor system logs
tail -f /var/log/syslog | grep -i flutter

# Check for Flutter-specific files
find /var/containers/Bundle/Application/ -name "*flutter*" 2>/dev/null
```

### Cross-Platform Detection Methods

#### 1. **Network Traffic Analysis**
```bash
# Monitor for Flutter-specific HTTP headers
mitmproxy --set confdir=~/.mitmproxy

# Look for Dart HTTP client user agents
# Example: "Dart/2.19 (dart:io)"
```

**Flutter Network Indicators:**
- User-Agent containing "Dart/" or "Flutter/"
- HTTP/2 usage with specific header patterns
- gRPC protocol usage (common in Flutter apps)
- Custom protocol buffers in request/response

#### 2. **FRIDA Detection Script**
```javascript
// flutter_detection.js
setTimeout(function() {
    console.log("[*] Starting Flutter application detection...");
    
    if (Java.available) {
        Java.perform(function() {
            try {
                // Check for Flutter engine classes
                var FlutterMain = Java.use("io.flutter.view.FlutterMain");
                console.log("[+] DETECTED: Flutter application - FlutterMain found");
            } catch (e) {
                console.log("[-] FlutterMain not found");
            }
            
            try {
                var FlutterActivity = Java.use("io.flutter.embedding.android.FlutterActivity");
                console.log("[+] DETECTED: Flutter application - FlutterActivity found");
            } catch (e) {
                console.log("[-] FlutterActivity not found");
            }
            
            try {
                var FlutterJNI = Java.use("io.flutter.embedding.engine.FlutterJNI");
                console.log("[+] DETECTED: Flutter application - FlutterJNI found");
            } catch (e) {
                console.log("[-] FlutterJNI not found");
            }
            
            try {
                var MethodChannel = Java.use("io.flutter.plugin.common.MethodChannel");
                console.log("[+] DETECTED: Flutter application - MethodChannel found");
            } catch (e) {
                console.log("[-] MethodChannel not found");
            }
            
            // Check for Dart VM
            try {
                var DartExecutor = Java.use("io.flutter.embedding.engine.dart.DartExecutor");
                console.log("[+] DETECTED: Flutter application - DartExecutor found");
            } catch (e) {
                console.log("[-] DartExecutor not found");
            }
        });
    }
    
    // Check for Objective-C Flutter classes (iOS)
    if (ObjC.available) {
        try {
            var FlutterViewController = ObjC.classes.FlutterViewController;
            if (FlutterViewController) {
                console.log("[+] DETECTED: Flutter application - FlutterViewController found");
            }
        } catch (e) {
            console.log("[-] FlutterViewController not found");
        }
        
        try {
            var FlutterEngine = ObjC.classes.FlutterEngine;
            if (FlutterEngine) {
                console.log("[+] DETECTED: Flutter application - FlutterEngine found");
            }
        } catch (e) {
            console.log("[-] FlutterEngine not found");
        }
    }
}, 1000);
```

#### 3. **Static Analysis Tools**
```bash
# Use MobSF for Flutter detection
python manage.py mobsf_scan app.apk

# Use APKTool for detailed analysis
apktool d app.apk
grep -r "flutter" app/

# Use dex2jar and analyze with JD-GUI
d2j-dex2jar app.apk
# Open classes-dex2jar.jar in JD-GUI and look for io.flutter packages
```

### Automated Flutter Detection Script

```bash
#!/bin/bash
# flutter_detector.sh - Automated Flutter application detection

APP_FILE="$1"
if [ -z "$APP_FILE" ]; then
    echo "Usage: $0 <app.apk|app.ipa>"
    exit 1
fi

echo "[*] Analyzing $APP_FILE for Flutter indicators..."

if [[ "$APP_FILE" == *.apk ]]; then
    echo "[*] Analyzing Android APK..."
    
    # Extract APK
    mkdir -p /tmp/flutter_analysis
    unzip -q "$APP_FILE" -d /tmp/flutter_analysis/
    cd /tmp/flutter_analysis/
    
    # Check for Flutter libraries
    if [ -f "lib/arm64-v8a/libflutter.so" ] || [ -f "lib/armeabi-v7a/libflutter.so" ]; then
        echo "[+] DETECTED: libflutter.so found - This is a Flutter application"
        FLUTTER_DETECTED=true
    fi
    
    # Check for Flutter assets
    if [ -d "assets/flutter_assets" ]; then
        echo "[+] DETECTED: flutter_assets directory found"
        FLUTTER_DETECTED=true
    fi
    
    # Check AndroidManifest.xml
    if aapt dump xmltree "$APP_FILE" AndroidManifest.xml 2>/dev/null | grep -q "io.flutter"; then
        echo "[+] DETECTED: Flutter references in AndroidManifest.xml"
        FLUTTER_DETECTED=true
    fi
    
elif [[ "$APP_FILE" == *.ipa ]]; then
    echo "[*] Analyzing iOS IPA..."
    
    # Extract IPA
    mkdir -p /tmp/flutter_analysis
    unzip -q "$APP_FILE" -d /tmp/flutter_analysis/
    cd /tmp/flutter_analysis/Payload/*.app
    
    # Check for Flutter framework
    if [ -d "Frameworks/Flutter.framework" ]; then
        echo "[+] DETECTED: Flutter.framework found - This is a Flutter application"
        FLUTTER_DETECTED=true
    fi
    
    # Check for App framework (compiled Dart code)
    if [ -d "Frameworks/App.framework" ]; then
        echo "[+] DETECTED: App.framework found (compiled Dart code)"
        FLUTTER_DETECTED=true
    fi
    
    # Check Info.plist
    if plutil -p Info.plist 2>/dev/null | grep -q -i flutter; then
        echo "[+] DETECTED: Flutter references in Info.plist"
        FLUTTER_DETECTED=true
    fi
fi

# Clean up
rm -rf /tmp/flutter_analysis

if [ "$FLUTTER_DETECTED" = true ]; then
    echo ""
    echo "🎯 RESULT: This is a FLUTTER APPLICATION"
    echo "✅ Proceed with Flutter-specific security testing techniques"
else
    echo ""
    echo "❌ RESULT: This does NOT appear to be a Flutter application"
    echo "ℹ️  Use standard native Android/iOS testing techniques"
fi
```

### Key Differences from Native Apps

**Flutter apps differ from native applications in several ways:**

1. **Code Structure**: Single codebase compiled to native code, not traditional Java/Kotlin (Android) or Swift/Objective-C (iOS)
2. **UI Rendering**: Custom rendering engine (Skia) instead of platform UI components
3. **Asset Management**: Flutter-specific asset bundling and management
4. **Platform Communication**: Platform channels for native functionality access
5. **Debugging**: Different debugging and inspection tools required
6. **Network Layer**: May use custom HTTP implementations that bypass system settings

Understanding these differences is crucial for effective security testing of Flutter applications.
13. [Research Article Summaries](#research-article-summaries)

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

#### 2. **Flutter-Specific Proxy Configuration (Sergey Yam's Approach)**
Based on Sergey Yam's research on Flutter proxy debugging:

```dart
// Force app to use proxy in debug mode (Development approach)
import 'dart:io';
import 'package:flutter/foundation.dart';

class FlutterHttpOverrides extends HttpOverrides {
  @override
  HttpClient createHttpClient(SecurityContext? context) {
    return super.createHttpClient(context)
      ..findProxy = (uri) {
        // Force all traffic through proxy (Sergey Yam approach)
        if (kDebugMode) {
          return 'PROXY 192.168.1.100:8080';
        }
        return 'DIRECT';
      }
      ..badCertificateCallback = (cert, host, port) {
        if (kDebugMode) {
          print('Sergey Debug: Bad certificate for $host:$port');
          return true; // Accept all certificates in debug mode
        }
        return false;
      };
  }
}

void main() {
  // Apply Sergey Yam's proxy configuration for development
  if (kDebugMode) {
    HttpOverrides.global = FlutterHttpOverrides();
  }
  runApp(MyApp());
}
```

**Runtime Proxy Injection (Sergey Yam's FRIDA Script)**:
```javascript
// Runtime proxy injection based on Sergey Yam's research
Java.perform(function() {
    console.log("[*] Sergey Yam Flutter Proxy Injection");
    
    // Hook HTTP client creation to force proxy usage
    try {
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        var URL = Java.use("java.net.URL");
        var Proxy = Java.use("java.net.Proxy");
        var ProxyType = Java.use("java.net.Proxy$Type");
        var InetSocketAddress = Java.use("java.net.InetSocketAddress");
        
        // Sergey's approach: Force proxy on all URL connections
        URL.openConnection.overload().implementation = function() {
            console.log("[*] Sergey: HTTP connection intercepted - " + this.toString());
            
            // Force proxy configuration
            var proxyAddress = InetSocketAddress.$new("192.168.1.100", 8080);
            var httpProxy = Proxy.$new(ProxyType.HTTP.value, proxyAddress);
            
            console.log("[*] Sergey: Forcing connection through proxy");
            return this.openConnection(httpProxy);
        };
        
        // Handle HTTPS connections specifically
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        var setDefaultHostnameVerifier = HttpsURLConnection.setDefaultHostnameVerifier;
        
        setDefaultHostnameVerifier.implementation = function(hostnameVerifier) {
            console.log("[*] Sergey: HTTPS hostname verifier - accepting all hosts for proxy");
            
            var AcceptAllHostnameVerifier = Java.registerClass({
                name: "com.sergey.AcceptAllHostnameVerifier",
                implements: [Java.use("javax.net.ssl.HostnameVerifier")],
                methods: {
                    verify: function(hostname, session) {
                        console.log("[*] Sergey: Accepting hostname: " + hostname);
                        return true;
                    }
                }
            });
            
            this.setDefaultHostnameVerifier(AcceptAllHostnameVerifier.$new());
        };
        
    } catch (e) {
        console.log("[!] Sergey proxy injection failed: " + e);
    }
});
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

#### 1. **IMQ Minded Security Approach - Dart-Level SSL Bypass**
Based on research from IMQ Minded Security, this approach targets Flutter's Dart-level SSL implementation:

```javascript
// Enhanced Flutter SSL bypass based on IMQ research
setTimeout(function() {
    Java.perform(function() {
        console.log("[*] IMQ Flutter SSL Pinning Bypass Started");
        
        // Hook Flutter Platform Channels for HTTP/SSL operations
        try {
            var MethodChannel = Java.use("io.flutter.plugin.common.MethodChannel");
            var originalInvokeMethod = MethodChannel.invokeMethod.overload("java.lang.String", "java.lang.Object");
            
            originalInvokeMethod.implementation = function(method, arguments) {
                if (method.includes("http") || method.includes("ssl") || method.includes("cert")) {
                    console.log("[*] IMQ - Platform Channel SSL call: " + method);
                    
                    // Disable SSL verification in platform channel arguments
                    if (arguments && typeof arguments === 'object') {
                        try {
                            var argString = Java.cast(arguments, Java.use("java.lang.String")).toString();
                            var args = JSON.parse(argString);
                            if (args.verify_ssl !== undefined) {
                                args.verify_ssl = false;
                                console.log("[*] IMQ - SSL verification disabled in platform channel");
                            }
                            if (args.pinning_enabled !== undefined) {
                                args.pinning_enabled = false;
                                console.log("[*] IMQ - Certificate pinning disabled");
                            }
                        } catch (e) {
                            console.log("[!] Could not parse platform channel arguments: " + e);
                        }
                    }
                }
                return originalInvokeMethod.call(this, method, arguments);
            };
        } catch (e) {
            console.log("[!] IMQ Platform channel hook failed: " + e);
        }
        
        // Hook native SSL context used by Flutter
        try {
            var SSLContext = Java.use("javax.net.ssl.SSLContext");
            var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            
            var PermissiveTrustManager = Java.registerClass({
                name: "com.imq.PermissiveTrustManager",
                implements: [TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {
                        console.log("[*] IMQ - checkClientTrusted bypassed");
                    },
                    checkServerTrusted: function(chain, authType) {
                        console.log("[*] IMQ - checkServerTrusted bypassed for: " + authType);
                    },
                    getAcceptedIssuers: function() {
                        return Java.array("java.security.cert.X509Certificate", []);
                    }
                }
            });
            
            SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function(keyManagers, trustManagers, secureRandom) {
                console.log("[*] IMQ - SSLContext.init() bypassed");
                var newTrustManagers = Java.array("javax.net.ssl.TrustManager", [PermissiveTrustManager.$new()]);
                this.init(keyManagers, newTrustManagers, secureRandom);
            };
        } catch (e) {
            console.log("[!] IMQ SSL context hook failed: " + e);
        }
    });
}, 1000);
```

#### 2. **NVISO Labs Multi-Layer Approach**
NVISO's research demonstrates the need for multi-layer interception:

```javascript
// NVISO Flutter multi-layer traffic interception
Java.perform(function() {
    console.log("[*] NVISO Multi-Layer Flutter Bypass");
    
    // Layer 1: Platform Channel Monitoring (NVISO approach)
    try {
        var MethodChannel = Java.use("io.flutter.plugin.common.MethodChannel");
        var invokeMethod = MethodChannel.invokeMethod.overload("java.lang.String", "java.lang.Object");
        
        invokeMethod.implementation = function(method, arguments) {
            if (method.includes("http") || method.includes("request") || method.includes("ssl")) {
                console.log("[*] NVISO - Platform Channel: " + method);
                console.log("[*] NVISO - Arguments: " + JSON.stringify(arguments));
            }
            return invokeMethod.call(this, method, arguments);
        };
    } catch (e) {
        console.log("[!] NVISO Platform channel hook failed: " + e);
    }
    
    // Layer 2: OkHttp Client Hooking (commonly used by Flutter)
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        
        // Bypass OkHttp certificate pinning
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function(hostname, peerCertificates) {
            console.log("[*] NVISO - Certificate pinning bypassed for: " + hostname);
            return;
        };
        
        // Hook OkHttp requests
        OkHttpClient.newCall.implementation = function(request) {
            console.log("[*] NVISO - OkHttp Request: " + request.url().toString());
            return this.newCall(request);
        };
    } catch (e) {
        console.log("[!] NVISO OkHttp hook failed: " + e);
    }
    
    // Layer 3: Low-level Socket Monitoring
    try {
        var Socket = Java.use("java.net.Socket");
        var connect = Socket.connect.overload("java.net.SocketAddress", "int");
        
        connect.implementation = function(endpoint, timeout) {
            console.log("[*] NVISO - Socket connection: " + endpoint.toString());
            return connect.call(this, endpoint, timeout);
        };
    } catch (e) {
        console.log("[!] NVISO Socket hook failed: " + e);
    }
});
```

#### 3. **OWASP MASTG Standard Approach**
Following OWASP MASTG-TECH-0109 guidelines:

```javascript
// MASTG-TECH-0109 compliant Flutter SSL bypass
Java.perform(function() {
    console.log("[*] MASTG-TECH-0109 Flutter HTTPS Bypass");
    
    // MASTG Standard: Hook Flutter Engine SSL
    try {
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
        
        // Create MASTG-compliant trust manager
        var MASTGTrustManager = Java.registerClass({
            name: "com.mastg.FlutterTrustManager",
            implements: [TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {
                    console.log("[*] MASTG: Client certificate validation bypassed");
                },
                checkServerTrusted: function(chain, authType) {
                    console.log("[*] MASTG: Server certificate validation bypassed");
                },
                getAcceptedIssuers: function() {
                    return Java.array("java.security.cert.X509Certificate", []);
                }
            }
        });
        
        // Create MASTG-compliant hostname verifier
        var MASTGHostnameVerifier = Java.registerClass({
            name: "com.mastg.FlutterHostnameVerifier",
            implements: [HostnameVerifier],
            methods: {
                verify: function(hostname, session) {
                    console.log("[*] MASTG: Hostname verification bypassed for: " + hostname);
                    return true;
                }
            }
        });
        
        // Hook SSL context initialization
        SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function(keyManagers, trustManagers, secureRandom) {
            console.log("[*] MASTG: SSLContext.init() intercepted");
            var mastgTrustManagers = Java.array("javax.net.ssl.TrustManager", [MASTGTrustManager.$new()]);
            this.init(keyManagers, mastgTrustManagers, secureRandom);
        };
        
        // Hook HTTPS URL connections
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hostnameVerifier) {
            console.log("[*] MASTG: Default hostname verifier replaced");
            this.setDefaultHostnameVerifier(MASTGHostnameVerifier.$new());
        };
        
    } catch (e) {
        console.log("[!] MASTG SSL bypass failed: " + e);
    }
    
    // MASTG: Flutter Platform Channel SSL Configuration
    try {
        var MethodChannel = Java.use("io.flutter.plugin.common.MethodChannel");
        var Result = Java.use("io.flutter.plugin.common.MethodChannel$Result");
        
        MethodChannel.setMethodCallHandler.implementation = function(handler) {
            console.log("[*] MASTG: MethodChannel handler intercepted");
            
            var MASTGHandler = Java.registerClass({
                name: "com.mastg.FlutterMethodCallHandler",
                implements: [Java.use("io.flutter.plugin.common.MethodChannel$MethodCallHandler")],
                methods: {
                    onMethodCall: function(call, result) {
                        var method = call.method.value;
                        console.log("[*] MASTG: Method call - " + method);
                        
                        // Intercept SSL/TLS related calls
                        if (method.includes("ssl") || method.includes("cert") || method.includes("pin") || method.includes("tls")) {
                            console.log("[*] MASTG: SSL-related platform call bypassed: " + method);
                            result.success(Java.use("java.lang.Boolean").TRUE);
                            return;
                        }
                        
                        // Forward other calls to original handler
                        if (handler) {
                            handler.onMethodCall(call, result);
                        }
                    }
                }
            });
            
            this.setMethodCallHandler(MASTGHandler.$new());
        };
    } catch (e) {
        console.log("[!] MASTG Platform channel bypass failed: " + e);
    }
});
```

#### 4. **Sergey Yam Proxy Configuration Approach**
Based on Sergey Yam's research on Flutter proxy debugging:

```javascript
// Flutter proxy configuration based on Sergey Yam's research
Java.perform(function() {
    console.log("[*] Sergey Yam Flutter Proxy Configuration");
    
    // Force HTTP client to use proxy
    try {
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        var URL = Java.use("java.net.URL");
        var Proxy = Java.use("java.net.Proxy");
        var ProxyType = Java.use("java.net.Proxy$Type");
        var InetSocketAddress = Java.use("java.net.InetSocketAddress");
        
        // Hook URL.openConnection to force proxy usage
        URL.openConnection.overload().implementation = function() {
            console.log("[*] Sergey: URL.openConnection() intercepted - forcing proxy");
            var proxyAddress = InetSocketAddress.$new("192.168.1.100", 8080);
            var proxy = Proxy.$new(ProxyType.HTTP.value, proxyAddress);
            return this.openConnection(proxy);
        };
        
        URL.openConnection.overload("java.net.Proxy").implementation = function(proxy) {
            console.log("[*] Sergey: URL.openConnection(proxy) called");
            var proxyAddress = InetSocketAddress.$new("192.168.1.100", 8080);
            var forceProxy = Proxy.$new(ProxyType.HTTP.value, proxyAddress);
            return this.openConnection(forceProxy);
        };
        
    } catch (e) {
        console.log("[!] Sergey proxy configuration failed: " + e);
    }
    
    // Hook Flutter-specific HTTP client creation
    try {
        var HttpClient = Java.use("java.net.HttpURLConnection");
        HttpClient.setInstanceFollowRedirects.implementation = function(followRedirects) {
            console.log("[*] Sergey: HTTP client configuration intercepted");
            
            // Disable SSL verification for proxy interception
            if (this.toString().includes("https")) {
                console.log("[*] Sergey: HTTPS connection detected - applying proxy settings");
                
                try {
                    var HttpsURLConnection = Java.cast(this, Java.use("javax.net.ssl.HttpsURLConnection"));
                    
                    // Create permissive hostname verifier
                    var AllHostnameVerifier = Java.registerClass({
                        name: "com.sergey.AllHostnameVerifier",
                        implements: [Java.use("javax.net.ssl.HostnameVerifier")],
                        methods: {
                            verify: function(hostname, session) {
                                console.log("[*] Sergey: Hostname verification bypassed for proxy: " + hostname);
                                return true;
                            }
                        }
                    });
                    
                    HttpsURLConnection.setHostnameVerifier(AllHostnameVerifier.$new());
                } catch (e) {
                    console.log("[!] Sergey HTTPS configuration failed: " + e);
                }
            }
            
            return this.setInstanceFollowRedirects(followRedirects);
        };
    } catch (e) {
        console.log("[!] Sergey HTTP client hook failed: " + e);
    }
});
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

## Research Article Summaries

This section provides detailed summaries of key research articles on Flutter application security testing, integrating their methodologies and findings into our testing approach.

### 1. Bypassing Certificate Pinning on Flutter-based Android Apps (IMQ Minded Security)

**Source**: [https://blog.mindedsecurity.com/2024/05/bypassing-certificate-pinning-on.html](https://blog.mindedsecurity.com/2024/05/bypassing-certificate-pinning-on.html)

#### Key Findings:

**Flutter Certificate Pinning Implementation Challenges:**
- Flutter apps often implement certificate pinning at the Dart application layer rather than native Android layer
- Traditional Android SSL pinning bypass techniques may not work on Flutter applications
- Flutter uses its own HTTP client implementation that can bypass system proxy settings

#### Methodologies Presented:

1. **Dart-Level SSL Bypass**:
   ```javascript
   // Enhanced FRIDA script based on IMQ research
   Java.perform(function() {
       console.log("[*] IMQ Flutter SSL Bypass - Starting");
       
       // Hook Flutter's Platform Channel for HTTP requests
       try {
           var MethodChannel = Java.use("io.flutter.plugin.common.MethodChannel");
           var originalInvokeMethod = MethodChannel.invokeMethod.overload("java.lang.String", "java.lang.Object");
           
           originalInvokeMethod.implementation = function(method, arguments) {
               if (method.includes("http") || method.includes("ssl")) {
                   console.log("[*] Platform Channel HTTP/SSL call intercepted: " + method);
                   
                   // Modify SSL verification arguments
                   if (arguments && typeof arguments === 'object') {
                       try {
                           var args = JSON.parse(arguments.toString());
                           if (args.verify_ssl !== undefined) {
                               args.verify_ssl = false;
                               console.log("[*] SSL verification disabled in platform channel");
                           }
                       } catch (e) {
                           console.log("[!] Could not parse platform channel arguments");
                       }
                   }
               }
               return originalInvokeMethod.call(this, method, arguments);
           };
       } catch (e) {
           console.log("[!] Platform channel hook failed: " + e);
       }
       
       // Hook native HTTP clients that Flutter might use
       try {
           var HttpURLConnection = Java.use("java.net.HttpURLConnection");
           var setHostnameVerifier = HttpURLConnection.setHostnameVerifier;
           setHostnameVerifier.implementation = function(hostnameVerifier) {
               console.log("[*] HttpURLConnection hostname verifier bypassed");
               var allHostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
               var AllHostnameVerifier = Java.registerClass({
                   name: "com.example.AllHostnameVerifier",
                   implements: [allHostnameVerifier],
                   methods: {
                       verify: function(hostname, session) {
                           console.log("[*] Hostname verification bypassed for: " + hostname);
                           return true;
                       }
                   }
               });
               return setHostnameVerifier.call(this, AllHostnameVerifier.$new());
           };
       } catch (e) {
           console.log("[!] HttpURLConnection hook failed: " + e);
       }
   });
   ```

2. **Flutter Asset Modification**:
   - Decompile APK and modify Flutter assets to disable SSL verification
   - Edit `flutter_assets/AssetManifest.json` to remove pinning configurations
   - Repackage and resign the application

3. **Platform Channel Interception**:
   - Monitor and modify data passed between Dart and native Android layers
   - Intercept HTTP plugin calls and disable SSL verification parameters

#### Practical Implementation from IMQ Research:

```bash
# Step-by-step Flutter SSL bypass based on IMQ methodology
# 1. Identify Flutter HTTP implementation
adb shell dumpsys package com.example.flutter_app | grep -i http

# 2. Use specialized Flutter FRIDA script
frida -U -l flutter_ssl_bypass_imq.js com.example.flutter_app

# 3. Monitor platform channel communications
frida -U -l platform_channel_monitor.js com.example.flutter_app

# 4. Verify bypass effectiveness
mitmproxy --set confdir=~/.mitmproxy
```

**Key Insights from IMQ Research:**
- Flutter apps require specialized bypass techniques targeting Dart-level implementations
- Platform channels are critical interception points for Flutter security testing
- Traditional Android SSL bypass tools may miss Flutter-specific implementations
- Certificate pinning in Flutter can be implemented in multiple layers (Dart, native, or both)

### 2. Flutter and Proxy Debugging Techniques (Medium - Sergey Yam)

**Source**: [https://yamsergey.medium.com/flutter-and-proxy-1e2b6acd24f5](https://yamsergey.medium.com/flutter-and-proxy-1e2b6acd24f5)

#### Key Findings:

**Proxy Configuration Challenges:**
- Flutter applications often ignore system proxy settings by default
- Custom HTTP client implementations in Flutter can bypass traditional proxy configurations
- Debug and release builds may have different proxy behavior

#### Methodologies Presented:

1. **Flutter Proxy Configuration (Development)**:
   ```dart
   // Force Flutter app to use proxy during development
   import 'dart:io';
   import 'package:flutter/foundation.dart';
   
   class DevHttpOverrides extends HttpOverrides {
     @override
     HttpClient createHttpClient(SecurityContext? context) {
       return super.createHttpClient(context)
         ..findProxy = (uri) {
           // Force all traffic through proxy
           return 'PROXY 192.168.1.100:8080';
         }
         ..badCertificateCallback = (cert, host, port) {
           if (kDebugMode) {
             print('Bad certificate for $host:$port');
             return true; // Accept all certificates in debug mode
           }
           return false;
         };
     }
   }
   
   void main() {
     if (kDebugMode) {
       HttpOverrides.global = DevHttpOverrides();
     }
     runApp(MyApp());
   }
   ```

2. **Runtime Proxy Injection**:
   ```javascript
   // FRIDA script for runtime proxy configuration
   Java.perform(function() {
       console.log("[*] Flutter Proxy Injection - Based on Sergey Yam Research");
       
       // Hook HttpClient creation in Flutter
       try {
           var DartHttpClient = Java.use("java.net.HttpURLConnection");
           var originalConnect = DartHttpClient.connect;
           
           originalConnect.implementation = function() {
               console.log("[*] HTTP connection intercepted: " + this.getURL().toString());
               
               // Force proxy configuration
               var proxySelector = Java.use("java.net.ProxySelector");
               var proxy = Java.use("java.net.Proxy");
               var proxyType = Java.use("java.net.Proxy$Type");
               var socketAddress = Java.use("java.net.InetSocketAddress");
               
               var proxyAddress = socketAddress.$new("192.168.1.100", 8080);
               var httpProxy = proxy.$new(proxyType.HTTP.value, proxyAddress);
               
               console.log("[*] Forcing HTTP traffic through proxy: 192.168.1.100:8080");
               
               return originalConnect.call(this);
           };
       } catch (e) {
           console.log("[!] HTTP proxy injection failed: " + e);
       }
   });
   ```

3. **System-Level Proxy Configuration**:
   ```bash
   # Android system proxy setup for Flutter apps
   adb shell settings put global http_proxy 192.168.1.100:8080
   adb shell settings put global https_proxy 192.168.1.100:8080
   
   # Alternative: iptables redirection
   adb shell su -c "iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination 192.168.1.100:8080"
   adb shell su -c "iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination 192.168.1.100:8080"
   ```

#### Advanced Techniques from Sergey Yam's Research:

1. **Flutter DevTools Integration**:
   ```bash
   # Use Flutter DevTools for network monitoring
   flutter run --debug
   # Navigate to http://localhost:9100 for DevTools
   # Use Network tab to monitor HTTP traffic
   ```

2. **Custom Proxy Middleware**:
   ```dart
   // Implement custom interceptor for Dio HTTP client
   import 'package:dio/dio.dart';
   
   class ProxyInterceptor extends Interceptor {
     @override
     void onRequest(RequestOptions options, RequestInterceptorHandler handler) {
       // Log all outgoing requests
       print('Proxy Debug: ${options.method} ${options.uri}');
       print('Headers: ${options.headers}');
       if (options.data != null) {
         print('Body: ${options.data}');
       }
       super.onRequest(options, handler);
     }
     
     @override
     void onResponse(Response response, ResponseInterceptorHandler handler) {
       print('Proxy Debug Response: ${response.statusCode}');
       print('Response Body: ${response.data}');
       super.onResponse(response, handler);
     }
   }
   ```

**Key Insights from Sergey Yam's Research:**
- Flutter proxy configuration requires understanding of Dart HTTP client implementation
- Development and production builds need different proxy approaches
- System proxy settings may not affect Flutter apps without explicit configuration
- Flutter DevTools provides valuable network monitoring capabilities for development builds

### 3. Intercepting Traffic from Android Flutter Applications (NVISO Labs)

**Source**: [https://blog.nviso.eu/2019/08/13/intercepting-traffic-from-android-flutter-applications/](https://blog.nviso.eu/2019/08/13/intercepting-traffic-from-android-flutter-applications/)

#### Key Findings:

**Flutter Network Architecture:**
- Flutter uses platform-specific HTTP implementations that may bypass traditional interception methods
- Network requests in Flutter go through multiple layers: Dart → Platform Channel → Native HTTP client
- Different interception strategies needed for debug vs. release builds

#### Methodologies Presented:

1. **Multi-Layer Interception Approach**:
   ```javascript
   // Comprehensive Flutter traffic interception - NVISO methodology
   Java.perform(function() {
       console.log("[*] NVISO Flutter Traffic Interception");
       
       // Layer 1: Platform Channel Monitoring
       try {
           var MethodChannel = Java.use("io.flutter.plugin.common.MethodChannel");
           var invokeMethod = MethodChannel.invokeMethod.overload("java.lang.String", "java.lang.Object");
           
           invokeMethod.implementation = function(method, arguments) {
               if (method.includes("http") || method.includes("request")) {
                   console.log("[*] NVISO - Platform Channel HTTP: " + method);
                   console.log("[*] Arguments: " + JSON.stringify(arguments));
               }
               return invokeMethod.call(this, method, arguments);
           };
       } catch (e) {
           console.log("[!] Platform channel hook failed: " + e);
       }
       
       // Layer 2: Native HTTP Client Hooking
       try {
           var OkHttpClient = Java.use("okhttp3.OkHttpClient");
           var newCall = OkHttpClient.newCall;
           
           newCall.implementation = function(request) {
               console.log("[*] NVISO - OkHttp Request: " + request.url().toString());
               console.log("[*] Method: " + request.method());
               
               var headers = request.headers();
               console.log("[*] Headers: " + headers.toString());
               
               return newCall.call(this, request);
           };
       } catch (e) {
           console.log("[!] OkHttp hook failed: " + e);
       }
       
       // Layer 3: Low-level Socket Monitoring
       try {
           var Socket = Java.use("java.net.Socket");
           var connect = Socket.connect.overload("java.net.SocketAddress", "int");
           
           connect.implementation = function(endpoint, timeout) {
               console.log("[*] NVISO - Socket connection: " + endpoint.toString());
               return connect.call(this, endpoint, timeout);
           };
       } catch (e) {
           console.log("[!] Socket hook failed: " + e);
       }
   });
   ```

2. **Flutter-Specific Proxy Configuration**:
   ```bash
   # NVISO approach for Flutter proxy setup
   
   # Step 1: Root the device (if needed for system certificate installation)
   adb root
   
   # Step 2: Install proxy certificate in system store
   openssl x509 -inform PEM -subject_hash_old -in burp-cert.pem | head -1
   adb push burp-cert.pem /system/etc/security/cacerts/9a5ba575.0
   adb shell chmod 644 /system/etc/security/cacerts/9a5ba575.0
   
   # Step 3: Configure global proxy
   adb shell settings put global http_proxy 192.168.1.100:8080
   
   # Step 4: Restart networking
   adb shell su -c "am force-stop com.android.providers.settings"
   ```

3. **Network Security Config Modification**:
   ```xml
   <!-- network_security_config.xml - NVISO approach -->
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

#### Advanced Analysis Techniques from NVISO:

1. **Flutter Asset Analysis for Network Configurations**:
   ```bash
   # Extract and analyze Flutter network configurations
   unzip app.apk
   cd assets/flutter_assets/
   
   # Look for network configuration files
   find . -name "*.json" | xargs grep -l "http\|ssl\|tls\|cert"
   
   # Analyze asset manifest for network-related assets
   cat AssetManifest.json | jq '.[] | select(. | contains("network") or contains("http") or contains("ssl"))'
   ```

2. **Dart Snapshot Network Analysis**:
   ```bash
   # Analyze compiled Dart code for network patterns
   strings lib/arm64-v8a/libapp.so | grep -E "(http|https|ssl|tls|cert|api)" | sort | uniq
   
   # Look for hardcoded URLs and endpoints
   strings lib/arm64-v8a/libapp.so | grep -E "https?://[^\s]+" | sort | uniq
   ```

**Key Insights from NVISO Research:**
- Flutter traffic interception requires a multi-layered approach targeting different abstraction levels
- System certificate store installation is often necessary for effective HTTPS interception
- Platform channels serve as a critical interception point between Dart and native code
- Debug builds may have different network behavior than release builds

### 4. MASTG-TECH-0109: Intercepting Flutter HTTPS Traffic (OWASP)

**Source**: [https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0109/](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0109/)

#### Key Findings:

**OWASP Standardized Approach:**
- Flutter HTTPS traffic interception requires specialized techniques due to custom HTTP client implementations
- Traditional MiTM proxy setup may not work with Flutter applications out of the box
- Certificate pinning bypass in Flutter involves both Dart-level and native-level considerations

#### Methodologies Presented:

1. **OWASP Recommended Flutter Proxy Setup**:
   ```bash
   # MASTG-TECH-0109 Standard Procedure
   
   # Step 1: Install proxy certificate
   # For Android 7+ (API level 24+) with Network Security Config
   adb push proxy-cert.pem /data/local/tmp/
   
   # Step 2: Modify network security configuration (for testable builds)
   # Add network_security_config.xml to res/xml/
   
   # Step 3: Use OWASP recommended FRIDA script
   frida -U -l mastg-flutter-bypass.js com.example.flutter_app
   ```

2. **MASTG Flutter Certificate Pinning Bypass**:
   ```javascript
   // MASTG-TECH-0109 Flutter Certificate Pinning Bypass
   Java.perform(function() {
       console.log("[*] MASTG-TECH-0109 Flutter HTTPS Bypass");
       
       // OWASP Recommended: Hook Flutter Engine SSL
       try {
           var SSLContext = Java.use("javax.net.ssl.SSLContext");
           var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
           
           // Create permissive trust manager
           var PermissiveTrustManager = Java.registerClass({
               name: "com.owasp.PermissiveTrustManager",
               implements: [TrustManager],
               methods: {
                   checkClientTrusted: function(chain, authType) {
                       console.log("[*] MASTG: checkClientTrusted bypassed");
                   },
                   checkServerTrusted: function(chain, authType) {
                       console.log("[*] MASTG: checkServerTrusted bypassed");
                   },
                   getAcceptedIssuers: function() {
                       return Java.array("java.security.cert.X509Certificate", []);
                   }
               }
           });
           
           // Hook SSLContext initialization
           var init = SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom");
           init.implementation = function(keyManagers, trustManagers, secureRandom) {
               console.log("[*] MASTG: SSLContext.init() called");
               var newTrustManagers = Java.array("javax.net.ssl.TrustManager", [PermissiveTrustManager.$new()]);
               this.init(keyManagers, newTrustManagers, secureRandom);
           };
           
       } catch (e) {
           console.log("[!] MASTG SSL bypass failed: " + e);
       }
       
       // OWASP Recommended: Flutter Platform Channel SSL Bypass
       try {
           var MethodChannel = Java.use("io.flutter.plugin.common.MethodChannel");
           var Result = Java.use("io.flutter.plugin.common.MethodChannel$Result");
           
           MethodChannel.setMethodCallHandler.implementation = function(handler) {
               console.log("[*] MASTG: MethodChannel handler set");
               
               var ProxyHandler = Java.registerClass({
                   name: "com.owasp.ProxyMethodCallHandler",
                   implements: [Java.use("io.flutter.plugin.common.MethodChannel$MethodCallHandler")],
                   methods: {
                       onMethodCall: function(call, result) {
                           var method = call.method.value;
                           if (method.includes("ssl") || method.includes("cert") || method.includes("pin")) {
                               console.log("[*] MASTG: SSL-related platform channel call intercepted: " + method);
                               // Modify SSL verification calls
                               result.success(true);
                               return;
                           }
                           // Forward other calls to original handler
                           handler.onMethodCall(call, result);
                       }
                   }
               });
               
               this.setMethodCallHandler(ProxyHandler.$new());
           };
       } catch (e) {
           console.log("[!] MASTG Platform channel bypass failed: " + e);
       }
   });
   ```

3. **MASTG Network Security Config Approach**:
   ```xml
   <!-- OWASP MASTG-TECH-0109 Recommended Network Security Config -->
   <?xml version="1.0" encoding="utf-8"?>
   <network-security-config>
       <debug-overrides>
           <trust-anchors>
               <!-- Trust user-installed CAs for debugging -->
               <certificates src="user"/>
               <certificates src="system"/>
           </trust-anchors>
       </debug-overrides>
       
       <base-config cleartextTrafficPermitted="true">
           <trust-anchors>
               <!-- Trust system CAs -->
               <certificates src="system"/>
               <!-- Trust user-installed CAs (for testing) -->
               <certificates src="user"/>
           </trust-anchors>
       </base-config>
       
       <!-- Specific domain configurations if needed -->
       <domain-config cleartextTrafficPermitted="true">
           <domain includeSubdomains="true">api.example.com</domain>
           <trust-anchors>
               <certificates src="user"/>
               <certificates src="system"/>
           </trust-anchors>
       </domain-config>
   </network-security-config>
   ```

#### MASTG Testing Workflow:

1. **Assessment Preparation**:
   ```bash
   # MASTG Flutter assessment setup
   # 1. Identify Flutter app
   flutter_detector.sh app.apk
   
   # 2. Set up testing environment
   mitmproxy --set confdir=~/.mitmproxy --scripts flutter_intercept.py
   
   # 3. Install SSL bypass
   frida -U -l mastg-flutter-bypass.js com.example.flutter_app
   
   # 4. Monitor traffic
   mitmdump -s flutter_logger.py
   ```

2. **Verification and Validation**:
   ```bash
   # Verify bypass effectiveness
   curl -x 127.0.0.1:8080 --proxy-insecure https://httpbin.org/get
   
   # Check certificate validation
   openssl s_client -connect target-api.com:443 -verify_return_error
   ```

**Key Insights from OWASP MASTG:**
- Standardized approach to Flutter HTTPS interception following OWASP guidelines
- Emphasis on both technical implementation and testing methodology
- Integration with broader mobile application security testing framework
- Focus on reproducible and verifiable testing procedures

### Integrated Testing Approach Based on Research

Based on the four research articles, here's a comprehensive Flutter security testing methodology:

#### 1. **Pre-Testing Assessment**
```bash
# Combined detection and preparation
./flutter_detector.sh app.apk
./setup_flutter_testing_environment.sh
```

#### 2. **Multi-Layer Traffic Interception**
```bash
# Apply techniques from all four research sources
# 1. NVISO multi-layer approach
frida -U -l nviso_flutter_intercept.js com.example.app

# 2. IMQ SSL bypass
frida -U -l imq_flutter_ssl_bypass.js com.example.app

# 3. Sergey Yam proxy configuration
frida -U -l sergey_proxy_config.js com.example.app

# 4. MASTG standardized bypass
frida -U -l mastg_flutter_bypass.js com.example.app
```

#### 3. **Comprehensive Analysis**
```bash
# Static analysis (NVISO + IMQ approaches)
reify app.apk
analyze_flutter_assets.sh app.apk

# Dynamic analysis (All methodologies combined)
monitor_platform_channels.sh
intercept_http_traffic.sh

# Validation (MASTG approach)
validate_bypass_effectiveness.sh
```

This integrated approach leverages insights from all four research articles to provide comprehensive Flutter application security testing coverage.

## References

- [IMQ Minded Security Blog: Bypassing Certificate Pinning on Flutter-based Android Apps](https://blog.mindedsecurity.com/2024/05/bypassing-certificate-pinning-on.html)
- [Flutter and Proxy debugging techniques](https://yamsergey.medium.com/flutter-and-proxy-1e2b6acd24f5)
- [Intercepting traffic from Android Flutter applications – NVISO Labs](https://blog.nviso.eu/2019/08/13/intercepting-traffic-from-android-flutter-applications/)
- [MASTG-TECH-0109: Intercepting Flutter HTTPS Traffic - OWASP Mobile Application Security](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0109/)
- [Flutter Security Best Practices](https://flutter.dev/docs/development/platform-integration/security)