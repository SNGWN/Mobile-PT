# Android Application Security Testing Guide

## Table of Contents
1. [Android Security Architecture](#android-security-architecture)
2. [Application Security Model](#application-security-model)
3. [Static Analysis Techniques](#static-analysis-techniques)
4. [Dynamic Analysis Methods](#dynamic-analysis-methods)
5. [Common Vulnerabilities](#common-vulnerabilities)
6. [Security Testing Tools](#security-testing-tools)
7. [Bypass Techniques](#bypass-techniques)
8. [Best Practices](#best-practices)

## Android Security Architecture

### Security Layers
```
┌─────────────────────────────────────┐
│          Applications               │ ← App Sandbox
├─────────────────────────────────────┤
│        Application Framework        │ ← Permission System
├─────────────────────────────────────┤
│         Native Libraries            │ ← Address Space Layout
├─────────────────────────────────────┤
│         Linux Kernel               │ ← Process Isolation
└─────────────────────────────────────┘
```

### Core Security Features

#### 1. **Application Sandbox**
- Each app runs in its own process
- Unique Linux user ID (UID) per app
- Isolated data directories
- Limited access to system resources

#### 2. **Permission System**
- Install-time permissions (API < 23)
- Runtime permissions (API ≥ 23)
- Custom permissions
- Permission groups

#### 3. **Application Signing**
- All APKs must be digitally signed
- Developer certificate validation
- App integrity verification
- Update authentication

#### 4. **SELinux (Security-Enhanced Linux)**
- Mandatory Access Control (MAC)
- Process isolation enforcement
- System call filtering
- Policy-based security

## Application Security Model

### APK Structure Security
```
app.apk
├── AndroidManifest.xml     # App permissions & components
├── classes.dex            # Compiled Java/Kotlin code
├── resources.arsc         # Compiled resources
├── lib/                   # Native libraries
│   └── arm64-v8a/        # Architecture-specific libs
├── assets/               # Raw assets
├── res/                  # Resources (layouts, strings)
└── META-INF/            # Signatures & certificates
    ├── MANIFEST.MF
    ├── CERT.SF
    └── CERT.RSA
```

### Component Security

#### Activities
- **Exported Activities**: Accessible from other apps
- **Intent Filters**: Define acceptable intents
- **Permission Protection**: Control access

#### Services
- **Background Processing**: Long-running operations
- **IPC Communication**: Inter-process communication
- **Binding Security**: Client-service connections

#### Broadcast Receivers
- **System Events**: Respond to system-wide broadcasts
- **Custom Broadcasts**: App-specific events
- **Security Implications**: Potential data leakage

#### Content Providers
- **Data Sharing**: Controlled access to app data
- **URI Permissions**: Fine-grained access control
- **SQL Injection Risks**: Database query vulnerabilities

## Static Analysis Techniques

### 1. **APK Extraction and Decompilation**

#### Extract APK from Device:
```bash
# List installed packages
adb shell pm list packages

# Get APK path
adb shell pm path com.example.app

# Pull APK from device
adb pull /data/app/com.example.app/base.apk
```

#### Decompilation Tools:
```bash
# JADX - Java decompiler
jadx -d output_dir app.apk

# APKTool - Resource extraction
apktool d app.apk

# Dex2jar - Convert DEX to JAR
d2j-dex2jar.sh app.apk
```

### 2. **Manifest Analysis**

#### AndroidManifest.xml Security Review:
```bash
# Extract and analyze manifest
aapt dump xmltree app.apk AndroidManifest.xml

# Check for dangerous permissions
grep -E "android.permission.(WRITE_EXTERNAL_STORAGE|READ_CONTACTS|ACCESS_FINE_LOCATION)" AndroidManifest.xml

# Look for exported components
grep -E "android:exported=\"true\"" AndroidManifest.xml
```

#### Key Security Checks:
- **Dangerous Permissions**: Location, contacts, storage
- **Exported Components**: Publicly accessible components
- **Debug Flag**: `android:debuggable="true"`
- **Backup Flag**: `android:allowBackup="true"`
- **Network Security**: `android:usesCleartextTraffic="true"`

### 3. **Code Analysis**

#### Automated Static Analysis:
```bash
# MobSF (Mobile Security Framework)
# Upload APK to web interface or use API

# QARK (Quick Android Review Kit)
qark --apk path/to/app.apk

# SonarQube with Android rules
sonar-scanner -Dsonar.projectKey=mobile-app
```

#### Manual Code Review Focus Areas:

##### Cryptography Implementation:
```java
// Weak examples to look for:
DES cipher = Cipher.getInstance("DES");           // Weak algorithm
MD5 hash = MessageDigest.getInstance("MD5");      // Weak hash
SecureRandom.getInstance("SHA1PRNG");             // Weak PRNG

// Hardcoded secrets:
String apiKey = "sk_live_abcd1234...";            // Hardcoded API key
String password = "admin123";                     // Hardcoded password
```

##### Insecure Data Storage:
```java
// Shared Preferences (unencrypted)
SharedPreferences prefs = getSharedPreferences("user_data", MODE_WORLD_READABLE);

// Internal storage issues
FileOutputStream fos = openFileOutput("secret.txt", MODE_WORLD_READABLE);

// External storage
File file = new File(Environment.getExternalStorageDirectory(), "sensitive.txt");
```

##### Network Security Issues:
```java
// Accepting all certificates
public void checkServerTrusted(X509Certificate[] chain, String authType) {
    // Empty implementation - accepts all certificates
}

// Allowing all hostnames
HostnameVerifier allHostsValid = new HostnameVerifier() {
    public boolean verify(String hostname, SSLSession session) {
        return true;  // Always return true
    }
};
```

## Dynamic Analysis Methods

### 1. **Runtime Application Testing**

#### FRIDA-based Analysis:
```javascript
// Hook cryptographic functions
Java.perform(function() {
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.getInstance.overload("java.lang.String").implementation = function(transformation) {
        console.log("[*] Cipher.getInstance called with: " + transformation);
        return this.getInstance(transformation);
    };
});
```

#### Memory Dumping:
```bash
# Dump process memory
frida-ps -U | grep com.example.app
gcore <pid>

# Search for sensitive data in memory
strings memory.dump | grep -i "password\|secret\|token"
```

### 2. **Network Traffic Analysis**

#### Proxy Configuration:
```bash
# Setup Burp Suite proxy
# Device Settings > WiFi > Network > Proxy > Manual
# Host: <burp-ip>, Port: 8080

# Install Burp CA certificate
# Export certificate from Burp
# Install as trusted certificate on device
```

#### Traffic Analysis Focus:
- **HTTP vs HTTPS**: Unencrypted communications
- **Certificate Validation**: Weak SSL/TLS implementations
- **API Security**: Authentication tokens, session management
- **Data Leakage**: Sensitive information in requests/responses

### 3. **File System Analysis**

#### Application Data Directories:
```bash
# App-specific directories (requires root)
/data/data/com.example.app/           # Private app data
/data/data/com.example.app/databases/ # SQLite databases
/data/data/com.example.app/shared_prefs/ # SharedPreferences
/data/data/com.example.app/files/     # Internal files

# External storage
/sdcard/Android/data/com.example.app/ # External app data
/sdcard/                              # Public external storage
```

#### Data Analysis:
```bash
# SQLite database analysis
sqlite3 database.db
.tables
.schema table_name
SELECT * FROM sensitive_table;

# SharedPreferences analysis
cat shared_prefs/user_prefs.xml | grep -i "password\|secret\|token"

# Log file analysis
logcat | grep "com.example.app"
```

## Common Vulnerabilities

### 1. **OWASP Mobile Top 10 (2016)**

#### M1: Improper Platform Usage
- **Description**: Misuse of platform features or failure to use security controls
- **Examples**: 
  - Misused permissions
  - Insecure data storage on external media
  - Weak authentication mechanisms

#### M2: Insecure Data Storage
- **Description**: Sensitive data stored without proper protection
- **Testing**:
```bash
# Check for sensitive data in databases
find /data/data/com.example.app -name "*.db" -exec sqlite3 {} ".dump" \; | grep -i "password\|credit"

# Check SharedPreferences
grep -r "password\|secret" /data/data/com.example.app/shared_prefs/
```

#### M3: Insecure Communication
- **Description**: Poor network communication protection
- **Testing**:
```bash
# Monitor network traffic
tcpdump -i any -w traffic.pcap host <device-ip>

# Check for HTTP usage
grep -i "http://" decompiled_code/
```

#### M4: Insecure Authentication
- **Description**: Weak authentication implementation
- **Testing**:
```javascript
// FRIDA script to bypass authentication
Java.perform(function() {
    var LoginActivity = Java.use("com.example.app.LoginActivity");
    LoginActivity.validateLogin.implementation = function(username, password) {
        console.log("[*] Login bypassed for: " + username);
        return true;
    };
});
```

#### M5: Insufficient Cryptography
- **Description**: Weak or broken cryptographic implementations
- **Examples**:
  - Weak algorithms (DES, MD5)
  - Hardcoded keys
  - Poor key management

### 2. **Android-Specific Vulnerabilities**

#### Intent-based Attacks:
```bash
# Test for intent injection
adb shell am start -n com.example.app/.MainActivity --es "extra_data" "malicious_payload"

# Broadcast injection
adb shell am broadcast -a com.example.app.CUSTOM_ACTION --es "data" "payload"
```

#### Component Hijacking:
```xml
<!-- Malicious app manifest -->
<activity android:name=".MaliciousActivity">
    <intent-filter android:priority="1000">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <data android:scheme="https" android:host="banking.com" />
    </intent-filter>
</activity>
```

## Security Testing Tools

### 1. **Static Analysis Tools**

#### MobSF (Mobile Security Framework):
```bash
# Docker installation
docker pull opensecurity/mobsf
docker run -it -p 8000:8000 opensecurity/mobsf:latest

# Upload APK via web interface
# Automated vulnerability scanning
```

#### QARK (Quick Android Review Kit):
```bash
# Installation
pip install qark

# Analysis
qark --apk path/to/app.apk --report-type html
```

#### Semgrep:
```bash
# Install semgrep
pip install semgrep

# Run Android-specific rules
semgrep --config=p/android-security path/to/source/
```

### 2. **Dynamic Analysis Tools**

#### FRIDA:
```bash
# Installation
pip install frida-tools

# Basic usage
frida -U -l script.js com.example.app
```

#### Xposed Framework:
```bash
# Requires rooted device
# Install Xposed Framework
# Develop custom modules for runtime manipulation
```

#### Drozer:
```bash
# Installation
pip install drozer

# Usage
adb forward tcp:31415 tcp:31415
drozer console connect
```

### 3. **Network Analysis Tools**

#### Burp Suite:
- Professional web security testing
- Mobile app traffic interception
- Automated vulnerability scanning

#### OWASP ZAP:
- Free alternative to Burp Suite
- Automated security testing
- REST API for automation

## Bypass Techniques

### 1. **Root Detection Bypass**
See [Root Detection Bypass Script](../../frida-scripts/android/root-detection-bypass.js)

### 2. **SSL Pinning Bypass**
See [SSL Pinning Bypass Script](../../frida-scripts/universal/ssl-pinning-bypass.js)

### 3. **Anti-Debugging Bypass**
```javascript
// Bypass ptrace detection
var ptrace = Module.findExportByName("libc.so", "ptrace");
if (ptrace) {
    Interceptor.attach(ptrace, {
        onEnter: function(args) {
            console.log("[*] ptrace called");
            args[0] = ptr(0); // PTRACE_TRACEME = 0
        }
    });
}
```

## Best Practices

### 1. **For Security Testers**
- Always test on dedicated devices
- Use updated tools and techniques
- Follow responsible disclosure
- Document findings thoroughly
- Provide clear remediation guidance

### 2. **For Developers**
- Implement defense in depth
- Use Android security best practices
- Regular security testing
- Keep dependencies updated
- Follow OWASP guidelines

### 3. **Testing Methodology**
1. **Information Gathering**: App analysis, permission review
2. **Static Analysis**: Code review, manifest analysis
3. **Dynamic Analysis**: Runtime testing, network analysis
4. **Vulnerability Assessment**: Security testing, penetration testing
5. **Reporting**: Documentation, recommendations

---

For practical examples and scripts, explore the Android-specific directories in this repository.