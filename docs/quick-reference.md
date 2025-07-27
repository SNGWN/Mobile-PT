# Mobile Penetration Testing Quick Reference

## Quick Commands & Scripts

### Android Quick Commands

#### APK Analysis
```bash
# Basic APK info
aapt dump badging app.apk | grep -E "(package|version|sdkVersion)"

# Extract APK from device
adb shell pm path com.example.app
adb pull /data/app/com.example.app/base.apk

# Quick decompile
jadx -d output app.apk
apktool d app.apk

# Search for secrets
grep -r -i "password\|secret\|key\|token\|api" output/
```

#### Device Commands
```bash
# Root check
adb shell su -c "id"

# Package info
adb shell pm list packages | grep example
adb shell pm dump com.example.app

# App directories
adb shell ls -la /data/data/com.example.app/
adb shell find /data/data/com.example.app/ -name "*.db"

# Clear app data
adb shell pm clear com.example.app
```

#### Network Testing
```bash
# Configure proxy
adb shell settings put global http_proxy <proxy_ip>:8080

# Check network config
adb shell cat /proc/net/route
adb shell netstat -tlnp
```

### iOS Quick Commands

#### Device Info
```bash
# Device information
ideviceinfo -k DeviceName
ideviceinfo -k ProductVersion
ideviceinfo -k WiFiAddress

# System logs
idevicesyslog | grep -i error

# Screenshot
idevicescreenshot ios_screen.png
```

#### App Analysis
```bash
# List installed apps
frida-ps -Uai

# Decrypt app (jailbroken device)
Clutch -i
Clutch -d "App Name"

# Extract headers
class-dump -H /path/to/binary > headers.h

# Binary analysis
otool -L binary
otool -hv binary | grep PIE
strings binary | grep -i "http"
```

### FRIDA Quick Scripts

#### Universal SSL Pinning Bypass
```bash
# Load and use SSL bypass
frida -U -l frida-scripts/universal/ssl-pinning-bypass.js com.example.app
```

#### Quick Function Hooking
```javascript
// Android
Java.perform(function() {
    var TargetClass = Java.use("com.example.TargetClass");
    TargetClass.targetMethod.implementation = function(arg) {
        console.log("Method called with: " + arg);
        return this.targetMethod(arg);
    };
});

// iOS
var method = ObjC.classes.TargetClass['- targetMethod:'];
Interceptor.attach(method.implementation, {
    onEnter: function(args) {
        console.log("Method called");
    }
});
```

## Common Vulnerability Patterns

### Android Vulnerabilities

#### 1. Insecure Data Storage
```bash
# Check for unencrypted data
adb shell find /data/data/com.example.app/ -name "*.xml" -exec cat {} \;
adb shell sqlite3 /data/data/com.example.app/databases/app.db ".dump"

# SharedPreferences
adb shell cat /data/data/com.example.app/shared_prefs/*.xml | grep -i "password\|secret"
```

#### 2. Exported Components
```bash
# Find exported activities
grep -n "exported.*true" AndroidManifest.xml

# Test intent injection
adb shell am start -n com.example.app/.VulnerableActivity --es "extra" "payload"
adb shell am broadcast -a com.example.app.ACTION --es "data" "malicious"
```

#### 3. Weak Cryptography
```bash
# Search for weak crypto
grep -r -i "DES\|MD5\|SHA1PRNG" source/
grep -r "AES.*ECB" source/
```

### iOS Vulnerabilities

#### 1. Insecure Keychain Usage
```bash
# Dump keychain (jailbroken)
keychain_dumper > keychain.txt

# Search for sensitive data
grep -i "password\|secret\|token" keychain.txt
```

#### 2. URL Scheme Hijacking
```bash
# Check URL schemes in Info.plist
plutil -p Info.plist | grep -A 5 "CFBundleURLSchemes"

# Test scheme handling
xcrun simctl openurl booted "customscheme://payload"
```

## Penetration Testing Workflows

### Initial Assessment (30 minutes)
```bash
# 1. APK/IPA Analysis
aapt dump badging app.apk  # Android
otool -L binary           # iOS

# 2. Static Analysis
mobsf-python -f app.apk   # Automated scan
grep -r "http://" source/ # Insecure protocols

# 3. Dynamic Setup
frida-ps -U              # Check FRIDA connection
burp_cert_install.sh     # Install proxy cert

# 4. Quick Vulnerability Checks
exported_components.sh   # Android
url_schemes.sh          # iOS
```

### Deep Analysis (2-4 hours)
```bash
# 1. Comprehensive Static Analysis
jadx -d full_output app.apk
semgrep --config=p/android-security source/

# 2. Binary Analysis
strings binary | grep -E "(https?://|password|secret)"
checksec binary  # Binary protections

# 3. Dynamic Analysis
frida -U -l comprehensive_hooks.js app
burp_active_scan.py

# 4. Custom Testing
business_logic_test.py
authentication_bypass_test.py
```

### Bypass Testing (1-2 hours)
```bash
# 1. Root/Jailbreak Detection
frida -U -l root-detection-bypass.js app

# 2. SSL Pinning
frida -U -l ssl-pinning-bypass.js app
burp_intercept_test.py

# 3. Anti-Debugging
frida -U -l anti-debugging-bypass.js app
gdb_attach_test.sh

# 4. Obfuscation
de4dot binary  # .NET
dex2jar app.apk  # Android
```

## Testing Cheat Sheets

### Android Security Testing
| Component | Test Command | Expected Result |
|-----------|--------------|-----------------|
| Root Detection | `frida -U -l root-bypass.js app` | Bypass successful |
| SSL Pinning | `burp_intercept.py` | Traffic intercepted |
| Exported Components | `drozer app.package.attacksurface` | No unnecessary exports |
| Data Storage | `adb shell find /data/data/app -name "*.db"` | Encrypted data |
| Permissions | `aapt dump permissions app.apk` | Minimal permissions |

### iOS Security Testing
| Component | Test Command | Expected Result |
|-----------|--------------|-----------------|
| Jailbreak Detection | `frida -H ip -l jb-bypass.js app` | Bypass successful |
| Keychain Security | `keychain_dumper` | No plaintext secrets |
| Code Signing | `codesign -vv binary` | Valid signature |
| Binary Protection | `otool -hv binary \| grep PIE` | PIE enabled |
| Network Security | `nscurl --ats-diagnostics url` | ATS compliant |

### Network Security Testing
| Protocol | Test Tool | Check For |
|----------|-----------|-----------|
| HTTPS | `nmap --script ssl-enum-ciphers` | Strong ciphers |
| Certificate | `openssl s_client -connect host:443` | Valid cert chain |
| HSTS | `curl -I https://host` | HSTS header |
| Certificate Pinning | `burp_bypass_test.py` | Pinning active |

## Reporting Templates

### Executive Summary Template
```markdown
## Security Assessment Summary

**Application**: [App Name]
**Platform**: [Android/iOS]
**Assessment Date**: [Date]
**Tester**: [Name]

### Risk Overview
- **Critical**: X findings
- **High**: X findings  
- **Medium**: X findings
- **Low**: X findings

### Key Findings
1. [Critical Finding 1]
2. [High Finding 1]
3. [Medium Finding 1]

### Recommendations
1. [Primary Recommendation]
2. [Secondary Recommendation]
```

### Technical Finding Template
```markdown
## [VULN-001] Vulnerability Title

**Risk Level**: [Critical/High/Medium/Low]
**Component**: [Affected Component]
**OWASP Category**: [M1-M10]

### Description
[Detailed description of the vulnerability]

### Technical Details
[Technical explanation and root cause]

### Proof of Concept
```bash
# Commands or code to reproduce
```

### Impact
[Business and technical impact]

### Remediation
[Specific fix recommendations]

### References
- [OWASP Mobile Top 10]
- [Vendor Security Guide]
```

## Emergency Response

### App Store Incident
```bash
# Quick analysis for emergency response
1. Extract APK/IPA immediately
2. Run automated security scan
3. Check for known vulnerabilities
4. Document evidence
5. Prepare incident report

# One-liner emergency scan
mobsf-python -f emergency_app.apk -o emergency_results/
```

### Breach Investigation
```bash
# Forensic analysis commands
adb shell dumpsys meminfo com.example.app  # Memory analysis
adb shell pm path com.example.app           # App location
adb shell stat /data/data/com.example.app   # Modification times
adb logcat -d | grep "com.example.app"      # Historical logs
```

---

**Quick Access Links:**
- [FRIDA Scripts](../frida-scripts/)
- [Security Checklist](security-testing-checklist.md)
- [Android Setup](tools/android-tools-setup.md)
- [iOS Setup](ios/tools-setup.md)