# Mobile Application Security Testing Checklist

## Overview
This comprehensive checklist covers both Android and iOS security testing based on OWASP Mobile Security Testing Guide (MSTG) and industry best practices.

## Pre-Testing Setup

### Environment Preparation
- [ ] **Testing Device Setup**
  - [ ] Dedicated testing device (rooted Android / jailbroken iOS)
  - [ ] Backup of original device state
  - [ ] Network isolation for testing
  - [ ] Development certificates installed

- [ ] **Tool Installation**
  - [ ] FRIDA framework setup
  - [ ] Burp Suite / OWASP ZAP configuration
  - [ ] Static analysis tools (MobSF, QARK, etc.)
  - [ ] Dynamic analysis tools
  - [ ] Device-specific tools (ADB, Xcode, etc.)

- [ ] **Application Acquisition**
  - [ ] Latest application version
  - [ ] Previous versions (if applicable)
  - [ ] Source code (if available)
  - [ ] API documentation

## Information Gathering

### Application Metadata
- [ ] **App Store Analysis**
  - [ ] App description and features
  - [ ] Developer information
  - [ ] Version history and update frequency
  - [ ] User reviews mentioning security issues
  - [ ] Privacy policy analysis

- [ ] **Technical Information**
  - [ ] Bundle identifier / Package name
  - [ ] Target API level / iOS version
  - [ ] Architecture support (ARM, x86, etc.)
  - [ ] File size and complexity indicators

### Permissions Analysis
- [ ] **Android Permissions**
  - [ ] Dangerous permissions requested
  - [ ] Custom permissions defined
  - [ ] Permission groups and protection levels
  - [ ] Runtime permission handling

- [ ] **iOS Permissions**
  - [ ] Privacy-sensitive permissions (Location, Camera, etc.)
  - [ ] Background modes
  - [ ] App Transport Security settings
  - [ ] Entitlements analysis

## Static Analysis

### Code Analysis
- [ ] **Android APK Analysis**
  - [ ] APK extraction and decompilation
  - [ ] Manifest file analysis
  - [ ] Resource inspection
  - [ ] Native library analysis
  - [ ] Certificate and signing verification

- [ ] **iOS IPA Analysis**
  - [ ] IPA extraction and analysis
  - [ ] Info.plist examination
  - [ ] Binary analysis (Mach-O)
  - [ ] Framework dependencies
  - [ ] Code signing verification

### Security Controls
- [ ] **Binary Protection**
  - [ ] Code obfuscation presence
  - [ ] Anti-debugging mechanisms
  - [ ] Anti-tampering controls
  - [ ] Root/jailbreak detection
  - [ ] ASLR/PIE implementation

- [ ] **Cryptography Implementation**
  - [ ] Encryption algorithm usage
  - [ ] Key management practices
  - [ ] Random number generation
  - [ ] Certificate pinning implementation
  - [ ] Hashing algorithm security

### Hardcoded Secrets
- [ ] **Sensitive Data Detection**
  - [ ] API keys and tokens
  - [ ] Database credentials
  - [ ] Encryption keys
  - [ ] Server URLs and endpoints
  - [ ] Debug information

## Dynamic Analysis

### Runtime Behavior
- [ ] **Application Flow Analysis**
  - [ ] Authentication mechanisms
  - [ ] Session management
  - [ ] Authorization controls
  - [ ] Business logic implementation
  - [ ] Error handling

- [ ] **API Communication**
  - [ ] Network traffic monitoring
  - [ ] API endpoint discovery
  - [ ] Request/response analysis
  - [ ] Authentication token handling
  - [ ] Data validation mechanisms

### Security Bypass Testing
- [ ] **Root/Jailbreak Detection Bypass**
  - [ ] Detection mechanism identification
  - [ ] Bypass technique implementation
  - [ ] Application behavior post-bypass
  - [ ] Security control effectiveness

- [ ] **SSL Pinning Bypass**
  - [ ] Pinning implementation analysis
  - [ ] Bypass using FRIDA scripts
  - [ ] Man-in-the-middle attack testing
  - [ ] Certificate validation bypass

- [ ] **Anti-Debugging Bypass**
  - [ ] Debugging protection analysis
  - [ ] FRIDA-based bypass
  - [ ] Runtime manipulation testing
  - [ ] Code flow analysis

## Vulnerability Assessment

### OWASP Mobile Top 10 Testing

#### M1: Improper Platform Usage
- [ ] **Permission Misuse**
  - [ ] Excessive permission requests
  - [ ] Inappropriate permission usage
  - [ ] Missing permission validations

- [ ] **Platform Feature Abuse**
  - [ ] WebView security misconfigurations
  - [ ] IPC mechanism vulnerabilities
  - [ ] Intent-based attacks (Android)

#### M2: Insecure Data Storage
- [ ] **Local Storage Analysis**
  - [ ] SQLite database security
  - [ ] SharedPreferences protection (Android)
  - [ ] Keychain implementation (iOS)
  - [ ] File system permissions
  - [ ] External storage usage

- [ ] **Memory Analysis**
  - [ ] Memory dump examination
  - [ ] Sensitive data in memory
  - [ ] Memory protection mechanisms

#### M3: Insecure Communication
- [ ] **Network Security**
  - [ ] HTTP vs HTTPS usage
  - [ ] Certificate validation
  - [ ] SSL/TLS configuration
  - [ ] Certificate pinning bypass

- [ ] **Data in Transit**
  - [ ] API security analysis
  - [ ] Data encryption in transit
  - [ ] Man-in-the-middle testing
  - [ ] Network protocol security

#### M4: Insecure Authentication
- [ ] **Authentication Mechanisms**
  - [ ] Username/password security
  - [ ] Biometric authentication bypass
  - [ ] Multi-factor authentication
  - [ ] Authentication token analysis

- [ ] **Session Management**
  - [ ] Session token security
  - [ ] Session timeout handling
  - [ ] Session invalidation
  - [ ] Concurrent session management

#### M5: Insufficient Cryptography
- [ ] **Cryptographic Implementation**
  - [ ] Algorithm strength assessment
  - [ ] Key generation and storage
  - [ ] Random number quality
  - [ ] Custom crypto implementations

#### M6: Insecure Authorization
- [ ] **Access Control Testing**
  - [ ] Privilege escalation attempts
  - [ ] Horizontal authorization bypass
  - [ ] Vertical authorization bypass
  - [ ] Direct object reference testing

#### M7: Client Code Quality
- [ ] **Code Quality Assessment**
  - [ ] Buffer overflow vulnerabilities
  - [ ] Format string vulnerabilities
  - [ ] Memory corruption issues
  - [ ] Input validation flaws

#### M8: Code Tampering
- [ ] **Anti-Tampering Controls**
  - [ ] Binary modification detection
  - [ ] Runtime integrity checks
  - [ ] Code injection protection
  - [ ] Hooking detection mechanisms

#### M9: Reverse Engineering
- [ **Anti-Reverse Engineering**
  - [ ] Code obfuscation effectiveness
  - [ ] Debug information removal
  - [ ] Symbol stripping
  - [ ] Anti-analysis techniques

#### M10: Extraneous Functionality
- [ ] **Hidden Features**
  - [ ] Debug functionality exposure
  - [ ] Test code in production
  - [ ] Administrative interfaces
  - [ ] Backdoor mechanisms

## Platform-Specific Testing

### Android-Specific Tests
- [ ] **Component Security**
  - [ ] Exported component analysis
  - [ ] Intent filter vulnerabilities
  - [ ] Content provider security
  - [ ] Broadcast receiver protection

- [ ] **Android Framework**
  - [ ] Custom URL scheme handling
  - [ ] Backup functionality testing
  - [ ] Debugging flag analysis
  - [ ] Package installer security

### iOS-Specific Tests
- [ ] **iOS Security Model**
  - [ ] App Sandbox verification
  - [ ] Keychain service usage
  - [ ] Touch ID/Face ID implementation
  - [ ] App Transport Security compliance

- [ ] **iOS Framework**
  - [ ] URL scheme vulnerability
  - [ ] UIWebView vs WKWebView usage
  - [ ] Background app refresh security
  - [ ] Universal links implementation

## Network Security Testing

### API Security
- [ ] **API Endpoint Testing**
  - [ ] Authentication bypass attempts
  - [ ] Authorization testing
  - [ ] Input validation testing
  - [ ] Rate limiting verification
  - [ ] API versioning security

- [ ] **Data Validation**
  - [ ] SQL injection testing
  - [ ] NoSQL injection testing
  - [ ] XML/JSON injection
  - [ ] Parameter pollution
  - [ ] File upload security

### Protocol Security
- [ ] **SSL/TLS Testing**
  - [ ] Protocol version analysis
  - [ ] Cipher suite evaluation
  - [ ] Certificate chain validation
  - [ ] Perfect Forward Secrecy
  - [ ] HSTS implementation

## Business Logic Testing

### Application Logic
- [ ] **Workflow Testing**
  - [ ] Business process bypass
  - [ ] State manipulation
  - [ ] Race condition testing
  - [ ] Time-based attacks
  - [ ] Logic bomb detection

### Financial/Payment Testing
- [ ] **Payment Security** (if applicable)
  - [ ] Payment flow analysis
  - [ ] Transaction integrity
  - [ ] Fraud prevention mechanisms
  - [ ] PCI DSS compliance
  - [ ] Tokenization implementation

## Privacy Testing

### Data Collection
- [ ] **Personal Data Handling**
  - [ ] Data minimization principles
  - [ ] Consent mechanisms
  - [ ] Data retention policies
  - [ ] Third-party data sharing
  - [ ] User control mechanisms

### Compliance Testing
- [ ] **Regulatory Compliance**
  - [ ] GDPR compliance (EU)
  - [ ] CCPA compliance (California)
  - [ ] COPPA compliance (Children)
  - [ ] Industry-specific regulations

## Reporting and Documentation

### Vulnerability Documentation
- [ ] **Finding Documentation**
  - [ ] Vulnerability classification (CVSS)
  - [ ] Risk assessment
  - [ ] Proof of concept development
  - [ ] Business impact analysis
  - [ ] Remediation recommendations

### Report Structure
- [ ] **Executive Summary**
  - [ ] High-level findings
  - [ ] Risk overview
  - [ ] Recommendations summary

- [ ] **Technical Details**
  - [ ] Detailed vulnerability descriptions
  - [ ] Exploitation steps
  - [ ] Supporting evidence (screenshots, logs)
  - [ ] Code snippets and examples

- [ ] **Remediation Guide**
  - [ ] Specific fix recommendations
  - [ ] Implementation guidelines
  - [ ] Best practices
  - [ ] Validation criteria

## Post-Testing Activities

### Validation
- [ ] **Remediation Verification**
  - [ ] Fix implementation review
  - [ ] Regression testing
  - [ ] Security control validation
  - [ ] Performance impact assessment

### Knowledge Transfer
- [ ] **Documentation Delivery**
  - [ ] Findings presentation
  - [ ] Training recommendations
  - [ ] Secure development guidance
  - [ ] Ongoing security measures

## Tools and Scripts Reference

### Static Analysis Tools
- **MobSF**: Automated security testing
- **QARK**: Android vulnerability scanner
- **Semgrep**: Code pattern analysis
- **class-dump**: iOS header extraction
- **Hopper/Ghidra**: Disassembly and analysis

### Dynamic Analysis Tools
- **FRIDA**: Runtime instrumentation
- **Burp Suite**: Web application testing
- **OWASP ZAP**: Security proxy
- **Drozer**: Android security testing
- **Instruments**: iOS performance analysis

### Custom Scripts
- **SSL Pinning Bypass**: [frida-scripts/universal/ssl-pinning-bypass.js](../frida-scripts/universal/ssl-pinning-bypass.js)
- **Root Detection Bypass**: [frida-scripts/android/root-detection-bypass.js](../frida-scripts/android/root-detection-bypass.js)
- **Jailbreak Detection Bypass**: [frida-scripts/ios/jailbreak-detection-bypass.js](../frida-scripts/ios/jailbreak-detection-bypass.js)
- **Crypto Monitor**: [frida-scripts/android/crypto-monitor.js](../frida-scripts/android/crypto-monitor.js)
- **Network Monitor**: [frida-scripts/android/network-monitor.js](../frida-scripts/android/network-monitor.js)

---

**Note**: This checklist should be adapted based on the specific application type, threat model, and testing scope. Not all items may be applicable to every application or testing scenario.