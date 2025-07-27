# FRIDA - Dynamic Instrumentation Toolkit

## Table of Contents
1. [What is FRIDA?](#what-is-frida)
2. [How FRIDA Works](#how-frida-works)
3. [FRIDA Architecture](#frida-architecture)
4. [Installation and Setup](#installation-and-setup)
5. [FRIDA Components](#frida-components)
6. [Script Structure](#script-structure)
7. [Common Use Cases](#common-use-cases)
8. [Advanced Features](#advanced-features)

## What is FRIDA?

FRIDA is a dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers. It allows you to inject snippets of JavaScript or your own library into native apps on Windows, macOS, GNU/Linux, iOS, Android, and QNX.

### Key Features:
- **Runtime Code Injection**: Inject JavaScript into running processes
- **API Hooking**: Intercept and modify function calls
- **Memory Manipulation**: Read and write process memory
- **Cross-Platform**: Works on Android, iOS, Windows, macOS, Linux
- **Real-time**: Modify behavior while the application is running
- **Scriptable**: Use JavaScript for instrumentation logic

## How FRIDA Works

### Core Mechanisms:

1. **Process Injection**: FRIDA injects a shared library (frida-agent) into the target process
2. **JavaScript Engine**: Embeds a V8 JavaScript engine for script execution
3. **Native Bridge**: Provides JavaScript bindings to native APIs
4. **Communication**: Uses JSON-RPC over various transports (TCP, USB, etc.)

### OS-Level Operations:

#### Android:
- Uses `ptrace()` system call for process attachment
- Leverages `dlopen()` and `dlsym()` for library loading
- Utilizes Android's `/proc/maps` for memory mapping information
- Exploits Linux kernel features for process control

#### iOS:
- Uses task ports for process access
- Leverages Mach-O binary format understanding
- Utilizes Darwin kernel features
- Works through Apple's debugging infrastructure

### Process Flow:
```
[FRIDA Client] ↔ [Transport Layer] ↔ [FRIDA Server] ↔ [Target Process]
      ↓                    ↓                ↓              ↓
   JavaScript          JSON-RPC         frida-agent    Native Code
```

## FRIDA Architecture

### Client-Server Architecture:

1. **FRIDA Client**: Command-line tools or custom applications
2. **Transport Layer**: Communication mechanism (USB, TCP, etc.)
3. **FRIDA Server**: Runs on target device, manages processes
4. **FRIDA Agent**: Injected into target process, executes scripts

### Key Components:

- **frida-core**: Core library implementing the instrumentation engine
- **frida-gum**: Code instrumentation library (hooking, stalking, etc.)
- **frida-server**: Server component running on target device
- **frida-agent**: JavaScript runtime injected into target process

### Memory Layout:
```
Target Process Memory Space:
┌─────────────────────────┐
│   Application Code      │
├─────────────────────────┤
│   System Libraries      │
├─────────────────────────┤
│   FRIDA Agent Library   │ ← Injected by FRIDA
├─────────────────────────┤
│   JavaScript Engine     │ ← V8 Runtime
├─────────────────────────┤
│   Script Memory         │ ← Your JavaScript
└─────────────────────────┘
```

## Installation and Setup

### Prerequisites:
- Python 3.7+ 
- Android SDK (for Android testing)
- Xcode (for iOS testing)
- USB Debugging enabled on mobile devices

### Installation:

#### Desktop/Laptop (Client):
```bash
# Install FRIDA client tools
pip install frida-tools

# Verify installation
frida --version
```

#### Android Device:
```bash
# Download frida-server for your architecture
# Check device architecture
adb shell getprop ro.product.cpu.abi

# Download appropriate frida-server
wget https://github.com/frida/frida/releases/download/16.1.4/frida-server-16.1.4-android-arm64.xz

# Extract and push to device
unxz frida-server-16.1.4-android-arm64.xz
adb push frida-server-16.1.4-android-arm64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server

# Start frida-server (requires root)
adb shell su -c "/data/local/tmp/frida-server &"
```

#### iOS Device (Jailbroken):
```bash
# Install via Cydia package manager
# Add FRIDA repository: https://build.frida.re

# Or manual installation
# Download frida-server for iOS
scp frida-server root@<device-ip>:/usr/sbin/
ssh root@<device-ip>
chmod +x /usr/sbin/frida-server
```

### Environment Setup:

#### Port Forwarding (Android):
```bash
# Forward FRIDA server port
adb forward tcp:27042 tcp:27042
```

#### Network Setup (iOS):
```bash
# Connect over network (WiFi)
frida -H <device-ip> -l script.js com.example.app
```

## FRIDA Components

### Core APIs:

1. **Java (Android)**:
   - `Java.perform()`: Execute code in Java runtime context
   - `Java.use()`: Get reference to Java class
   - `Java.choose()`: Find instances of Java class

2. **ObjC (iOS)**:
   - `ObjC.classes`: Access Objective-C classes
   - `ObjC.protocols`: Access protocols
   - `new ObjC.Object()`: Create ObjC objects

3. **Native**:
   - `Module`: Access loaded modules/libraries
   - `Memory`: Read/write process memory
   - `NativeFunction`: Call native functions

### Hooking Mechanisms:

1. **Interceptor**: Function interception
2. **Stalker**: Code tracing and coverage
3. **CModule**: Embed C code for performance

## Script Structure

### Basic Script Template:
```javascript
// FRIDA Script Structure
console.log("[*] Script loaded");

// Java code (Android)
Java.perform(function() {
    console.log("[*] Inside Java perform");
    
    // Hook a Java method
    var TargetClass = Java.use("com.example.TargetClass");
    TargetClass.targetMethod.implementation = function(arg1, arg2) {
        console.log("[*] targetMethod called with: " + arg1 + ", " + arg2);
        
        // Call original method
        var result = this.targetMethod(arg1, arg2);
        
        console.log("[*] Original result: " + result);
        return result;
    };
});

// Native code hooking
var nativeFunction = Module.findExportByName("libc.so", "strcmp");
if (nativeFunction) {
    Interceptor.attach(nativeFunction, {
        onEnter: function(args) {
            var str1 = Memory.readUtf8String(args[0]);
            var str2 = Memory.readUtf8String(args[1]);
            console.log("[*] strcmp called: " + str1 + " vs " + str2);
        },
        onLeave: function(retval) {
            console.log("[*] strcmp result: " + retval);
        }
    });
}
```

### Script Categories:

1. **Initialization Scripts**: Setup and environment detection
2. **Hooking Scripts**: Function interception and modification
3. **Data Extraction Scripts**: Extract sensitive information
4. **Bypass Scripts**: Circumvent security controls
5. **Utility Scripts**: Helper functions and common operations

### Best Practices:

1. **Error Handling**: Always wrap code in try-catch blocks
2. **Logging**: Use consistent logging for debugging
3. **Performance**: Minimize overhead in hooks
4. **Modularity**: Break complex scripts into modules
5. **Documentation**: Comment your code thoroughly

## Common Use Cases

### Security Testing:
- SSL Certificate Pinning Bypass
- Root/Jailbreak Detection Bypass
- Anti-debugging Bypass
- Encryption Key Extraction
- API Authentication Bypass

### Reverse Engineering:
- Function Flow Analysis
- Parameter Inspection
- Return Value Modification
- Algorithm Understanding
- Vulnerability Discovery

### Dynamic Analysis:
- Runtime Behavior Monitoring
- Data Flow Tracking
- API Call Logging
- Memory Dump Analysis
- Network Traffic Inspection

## Advanced Features

### Code Tracing with Stalker:
```javascript
// Trace function execution
var targetFunction = Module.findExportByName("libssl.so", "SSL_write");
Stalker.follow(Process.getCurrentThreadId(), {
    events: {
        call: true,
        ret: true
    },
    onReceive: function(events) {
        console.log("Traced " + events.length + " events");
    }
});
```

### Custom C Code with CModule:
```javascript
// Embed C code for performance
var cm = new CModule(`
    #include <string.h>
    
    int custom_strcmp(const char *s1, const char *s2) {
        printf("Custom strcmp: %s vs %s\\n", s1, s2);
        return strcmp(s1, s2);
    }
`);

var customStrcmp = new NativeFunction(cm.custom_strcmp, 'int', ['pointer', 'pointer']);
```

### Memory Scanning:
```javascript
// Scan for patterns in memory
Memory.scan(Module.findBaseAddress("libssl.so"), 0x1000, "41 41 41 41", {
    onMatch: function(address, size) {
        console.log("Found pattern at: " + address);
    },
    onComplete: function() {
        console.log("Scan complete");
    }
});
```

---

For more specific examples and ready-to-use scripts, check the `frida-scripts` directory in this repository.