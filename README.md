# 📱 Mobile Penetration Testing Toolkit

A comprehensive collection of tools, scripts, and documentation for mobile application security testing on Android and iOS platforms.

## 🚀 Quick Start

### Repository Structure
```
Mobile-PT/
├── docs/
│   ├── android/          # Android security documentation
│   ├── ios/              # iOS security documentation  
│   ├── frida/            # FRIDA toolkit documentation
│   └── tools/            # Tool-specific guides
├── frida-scripts/        # Ready-to-use FRIDA scripts
│   ├── android/          # Android-specific scripts
│   ├── ios/              # iOS-specific scripts
│   └── universal/        # Cross-platform scripts
├── Applications/         # Sample vulnerable apps for testing
└── books/               # Reference materials and guides
```

### Getting Started
1. **Android Testing**: Start with [Android Setup Guide](docs/android/)
2. **iOS Testing**: Begin with [iOS Setup Guide](docs/ios/)
3. **FRIDA**: Learn dynamic instrumentation with [FRIDA Documentation](docs/frida/)
4. **Tools**: Explore security tools in [Tools Directory](docs/tools/)

## 📚 Documentation

### Android Security
- [Android Application Architecture](docs/android/1.3%20--%20Android%20Application%20Architecture.md)
- [Android Security Model](docs/android/1.8%20--%20User%20Permission%20and%20Application%20Permission.md)
- [Android File Structure](docs/android/1.9%20--%20Android%20File%20Structure.md)
- [Build Process](docs/android/1.7%20--%20Android%20Application%20Build%20Process.md)

### iOS Security
- [iOS Security Testing Guide](docs/ios/README.md)
- [iOS Architecture Overview](docs/ios/README.md#ios-architecture-overview)
- [iOS Security Model](docs/ios/README.md#ios-security-model)
- [Static & Dynamic Analysis](docs/ios/README.md#static-analysis)

### FRIDA Framework
- [FRIDA Overview](docs/frida/README.md)
- [Android Setup](docs/frida/android-setup.md)
- [iOS Setup](docs/frida/ios-setup.md)
- [Script Development](docs/frida/README.md#script-structure)

### Security Tools
- [ADB Commands](docs/tools/ADB%20Commands.md)
- [Drozer Framework](docs/tools/Drozer.md)
- [Burp Suite Configuration](docs/tools/Burp%20Suite%20Configuration%20for%20Android%20API%20Greater%20than%2023.md)
- [Androguard](docs/tools/androguard.md)

## 🎯 FRIDA Scripts Collection

### Universal Scripts
- [SSL Pinning Bypass](frida-scripts/universal/ssl-pinning-bypass.js) - Works on Android & iOS

### Android Scripts
- [Root Detection Bypass](frida-scripts/android/root-detection-bypass.js)
- [Anti-Debugging Bypass](frida-scripts/android/) 
- [Certificate Pinning Bypass](frida-scripts/android/)

### iOS Scripts  
- [Jailbreak Detection Bypass](frida-scripts/ios/jailbreak-detection-bypass.js)
- [Touch ID/Face ID Bypass](frida-scripts/ios/)
- [SSL Pinning Bypass](frida-scripts/ios/)

## 🎥 Video Tutorials - Pentesting Club

### Complete Playlists
[![Mobile App Pentesting Playlist](https://img.youtube.com/vi/Dnn2uHv7wwY/maxresdefault.jpg)](https://www.youtube.com/playlist?list=PL--2vyReuUpSCMs57J3FhZrD-24Rcp5H2)
**Complete Mobile Application Security Testing Playlist**

### Android Security Testing

[![Android SSL Pinning Bypass with Frida](https://img.youtube.com/vi/SXtiVN7Trtw/maxresdefault.jpg)](https://www.youtube.com/watch?v=SXtiVN7Trtw)
**Android SSL Pinning Bypass with FRIDA**

[![Burp Suite Configuration for Android](https://img.youtube.com/vi/1721lyUtfYY/maxresdefault.jpg)](https://www.youtube.com/watch?v=1721lyUtfYY)
**Burp Suite Configuration for Android Applications**

[![Android Static Analysis with MobSF](https://img.youtube.com/vi/XHWDNcw_QKw/maxresdefault.jpg)](https://www.youtube.com/watch?v=XHWDNcw_QKw)
**Android Static Analysis with Mobile Security Framework**

[![Drozer Framework Tutorial](https://img.youtube.com/vi/QsDa0iYQfOQ/maxresdefault.jpg)](https://www.youtube.com/watch?v=QsDa0iYQfOQ)
**Complete Drozer Framework for Android Testing**

### iOS Security Testing

[![iOS Application Security Testing](https://img.youtube.com/vi/bw4eE1zJp1Y/maxresdefault.jpg)](https://www.youtube.com/watch?v=bw4eE1zJp1Y)
**iOS Application Security Testing Basics**

[![iOS SSL Pinning Bypass](https://img.youtube.com/vi/Kkqj8zjB8uY/maxresdefault.jpg)](https://www.youtube.com/watch?v=Kkqj8zjB8uY)
**iOS SSL Certificate Pinning Bypass Techniques**

### FRIDA Framework

[![FRIDA Crash Course](https://img.youtube.com/vi/uc1mbN9EJKQ/maxresdefault.jpg)](https://www.youtube.com/watch?v=uc1mbN9EJKQ)
**FRIDA Framework Complete Tutorial**

[![Advanced FRIDA Scripting](https://img.youtube.com/vi/CLVMOLzZJhI/maxresdefault.jpg)](https://www.youtube.com/watch?v=CLVMOLzZJhI)
**Advanced FRIDA Scripting Techniques**

### Mobile OWASP Testing

[![OWASP Mobile Top 10](https://img.youtube.com/vi/qEeEuFPjz7s/maxresdefault.jpg)](https://www.youtube.com/watch?v=qEeEuFPjz7s)
**OWASP Mobile Security Testing Guide**

[![Mobile App Vulnerability Assessment](https://img.youtube.com/vi/YvJ2IpXvtoo/maxresdefault.jpg)](https://www.youtube.com/watch?v=YvJ2IpXvtoo)
**Complete Mobile Application Vulnerability Assessment**

## 📱 Sample Applications

The `Applications/` directory contains various vulnerable applications for testing:

### Android Applications
- **DIVA** (Damn Insecure and Vulnerable App)
- **InsecureBankv2** - Banking app with vulnerabilities
- **UnCrackable Series** - Reverse engineering challenges
- **OWASP GoatDroid** - Deliberately vulnerable app
- **VulnApp** - General vulnerability testing

### Testing Environment
- **Drozer Agent** - For component analysis
- **Certificate Pinning Test Apps** - For bypass testing
- **Root Detection Apps** - For evasion testing

## 🛠️ Essential Tools Setup

### Android Testing Tools
```bash
# ADB (Android Debug Bridge)
sudo apt-get install android-tools-adb

# FRIDA for Android
pip install frida-tools
# Download frida-server for your device architecture

# MobSF (Mobile Security Framework)
docker pull opensecurity/mobsf
```

### iOS Testing Tools
```bash
# Xcode (macOS only)
# Install from App Store

# FRIDA for iOS
pip install frida-tools
# Requires jailbroken device

# iOS Security Tools
brew install class-dump
brew install ios-deploy
```

### Network Testing
```bash
# Burp Suite Community/Professional
# OWASP ZAP
# Wireshark for traffic analysis
```

## 🔒 Security Testing Methodology

### 1. **Information Gathering**
- App store analysis
- Permissions review
- Technology stack identification

### 2. **Static Analysis**
- Code review
- Binary analysis  
- Configuration assessment
- Hardcoded secrets detection

### 3. **Dynamic Analysis**
- Runtime behavior monitoring
- Network traffic analysis
- Memory dumping
- API testing

### 4. **Security Testing**
- Authentication bypass
- Authorization flaws
- Input validation
- Data storage security
- Communication security

### 5. **Reporting**
- Vulnerability classification
- Risk assessment
- Remediation guidance
- Proof of concepts

## 🎓 Learning Resources

### Books (Available in `/books/` directory)
- **Android Security Internals** - In-depth Android security architecture
- **Mobile Application Security** - Comprehensive mobile security guide
- **OWASP Mobile Security Testing Guide** - Industry standard testing methodology

### Online Resources
- [OWASP Mobile Security Project](https://owasp.org/www-project-mobile-security/)
- [FRIDA Documentation](https://frida.re/docs/)
- [Android Security Documentation](https://source.android.com/security)
- [iOS Security Guide](https://support.apple.com/guide/security/)

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add your improvements
4. Submit a pull request

### Areas for Contribution
- New FRIDA scripts
- Additional vulnerable apps
- Documentation improvements
- Tool integration guides
- Video tutorial suggestions

## ⚠️ Legal Disclaimer

This repository is for educational and authorized security testing purposes only. Always ensure you have proper authorization before testing any applications or systems. The authors are not responsible for any misuse of the tools and information provided.

## 📧 Contact & Support

- **Issues**: Use GitHub Issues for bug reports and feature requests
- **Discussions**: Join the community discussions
- **Security Research**: Share your findings responsibly

---

**Happy Hacking! 🔐📱**
