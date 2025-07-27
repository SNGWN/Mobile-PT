# FRIDA Scripts Collection

This directory contains ready-to-use FRIDA scripts for mobile application security testing.

## Directory Structure

```
frida-scripts/
├── universal/          # Cross-platform scripts (Android & iOS)
├── android/           # Android-specific scripts
├── ios/              # iOS-specific scripts
└── README.md         # This file
```

## Universal Scripts

### [ssl-pinning-bypass.js](universal/ssl-pinning-bypass.js)
**Purpose**: Bypasses SSL certificate pinning on both Android and iOS
**Targets**: 
- Android: OkHTTP3, HttpsURLConnection, X509TrustManager, Volley
- iOS: NSURLSession, SecTrustEvaluate, tls_helper_create_peer_trust

**Usage**:
```bash
frida -U -l universal/ssl-pinning-bypass.js com.example.app
```

## Android Scripts

### [root-detection-bypass.js](android/root-detection-bypass.js)
**Purpose**: Bypasses common root detection mechanisms
**Targets**:
- RootBeer library
- File system checks
- Runtime.exec() commands
- Package manager queries
- Build properties

**Usage**:
```bash
frida -U -l android/root-detection-bypass.js com.example.app
```

### [anti-debugging-bypass.js](android/anti-debugging-bypass.js)
**Purpose**: Bypasses anti-debugging techniques
**Targets**:
- Debug.isDebuggerConnected()
- ApplicationInfo.FLAG_DEBUGGABLE
- Native ptrace detection
- Timing-based detection
- Process name checks

**Usage**:
```bash
frida -U -l android/anti-debugging-bypass.js com.example.app
```

## iOS Scripts

### [jailbreak-detection-bypass.js](ios/jailbreak-detection-bypass.js)
**Purpose**: Bypasses jailbreak detection mechanisms
**Targets**:
- File existence checks
- URL scheme detection (cydia://)
- Sandbox violation detection
- System call monitoring
- Anti-debugging (ptrace)

**Usage**:
```bash
frida -H device-ip -l ios/jailbreak-detection-bypass.js com.example.app
```

### [biometric-bypass.js](ios/biometric-bypass.js)
**Purpose**: Bypasses Touch ID/Face ID authentication
**Targets**:
- LAContext evaluatePolicy
- SecItemCopyMatching
- UIAlertController biometric prompts
- Custom biometric implementations

**Usage**:
```bash
frida -H device-ip -l ios/biometric-bypass.js com.example.app
```

## Usage Guidelines

### Basic Usage Pattern
```bash
# Android (USB)
frida -U -l script.js package.name

# Android (Network)
frida -H device-ip -l script.js package.name

# iOS (Network)
frida -H device-ip -l script.js bundle.identifier

# With spawn (start app)
frida -U -f package.name -l script.js

# Attach to running process
frida -U package.name -l script.js
```

### Script Modification
Most scripts can be customized by modifying:
- Target package/bundle identifiers
- Detection patterns (file paths, strings)
- Return values for bypassed functions
- Logging verbosity

### Combining Scripts
You can combine multiple scripts:
```bash
frida -U -l universal/ssl-pinning-bypass.js -l android/root-detection-bypass.js com.example.app
```

## Development Guidelines

### Script Structure
```javascript
// Script header with description and purpose
console.log("[*] Script name loaded");

// Platform detection
if (Java.available) {
    // Android-specific code
    Java.perform(function() {
        // Hook Java methods
    });
}

if (ObjC.available) {
    // iOS-specific code
    // Hook Objective-C methods
}

// Native code hooks (cross-platform)
var nativeFunction = Module.findExportByName("library", "function");
if (nativeFunction) {
    Interceptor.attach(nativeFunction, {
        onEnter: function(args) {
            // Log or modify arguments
        },
        onLeave: function(retval) {
            // Log or modify return value
        }
    });
}

console.log("[*] Script setup complete!");
```

### Best Practices
1. **Error Handling**: Always wrap hooks in try-catch blocks
2. **Logging**: Use consistent logging format `[*]`, `[+]`, `[-]`
3. **Platform Detection**: Check for Java/ObjC availability
4. **Graceful Degradation**: Continue if specific hooks fail
5. **Documentation**: Comment complex hooks and modifications

### Testing Scripts
Before using scripts in production:
1. Test on known vulnerable applications
2. Verify hooks are working with logging
3. Test on different OS versions
4. Check for performance impact
5. Validate bypass effectiveness

## Contributing

### Adding New Scripts
1. Follow the established directory structure
2. Use consistent naming conventions
3. Include comprehensive documentation
4. Test on multiple applications and OS versions
5. Update this README.md

### Script Template
```javascript
/*
 * Script Name - Brief Description
 * Purpose: Detailed description of what the script does
 * Targets: List of specific components/libraries targeted
 * Author: Your name/handle
 * Version: 1.0
 */

console.log("[*] Script Name loaded");

// Your implementation here

console.log("[*] Script Name setup complete!");
```

## Troubleshooting

### Common Issues

1. **Script Not Loading**
   - Check file path and permissions
   - Verify FRIDA server is running
   - Check device connectivity

2. **Hooks Not Working**
   - Verify target methods exist in the application
   - Check for obfuscated method names
   - Use `Java.enumerateLoadedClasses()` to find classes

3. **Application Crashes**
   - Add error handling to hooks
   - Check for null pointers
   - Reduce hook complexity

4. **Detection Still Works**
   - Application may use different detection methods
   - Check for native/JNI implementations
   - Consider additional bypass techniques

### Debugging Scripts
```javascript
// Enable verbose logging
Java.perform(function() {
    console.log("[*] Available classes:");
    Java.enumerateLoadedClasses({
        onMatch: function(name, handle) {
            if (name.includes("Security") || name.includes("Root")) {
                console.log("Found: " + name);
            }
        },
        onComplete: function() {
            console.log("[*] Class enumeration complete");
        }
    });
});
```

## Legal and Ethical Considerations

### Usage Guidelines
- Only use on applications you own or have authorization to test
- Respect intellectual property rights
- Follow responsible disclosure practices
- Comply with local laws and regulations

### Educational Purpose
These scripts are provided for:
- Security research and education
- Authorized penetration testing
- Application security assessment
- Learning mobile security concepts

## Resources

### FRIDA Documentation
- [Official FRIDA Docs](https://frida.re/docs/)
- [FRIDA CodeShare](https://codeshare.frida.re/)
- [FRIDA API Reference](https://frida.re/docs/javascript-api/)

### Mobile Security Resources
- [OWASP Mobile Security](https://owasp.org/www-project-mobile-security/)
- [Android Security](https://source.android.com/security)
- [iOS Security Guide](https://support.apple.com/guide/security/)

### Community
- [FRIDA GitHub](https://github.com/frida/frida)
- [Mobile Security Communities](https://github.com/topics/mobile-security)
- [Security Research Forums](https://www.reddit.com/r/ReverseEngineering/)

---

**Happy scripting! 🔍📱**