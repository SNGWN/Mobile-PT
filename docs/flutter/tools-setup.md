# Flutter Security Testing Tools Setup

## Table of Contents
1. [Flutter SDK Installation](#flutter-sdk-installation)
2. [Development Environment Setup](#development-environment-setup)
3. [Security Testing Tools](#security-testing-tools)
4. [Flutter-Specific Tools](#flutter-specific-tools)
5. [Static Analysis Tools](#static-analysis-tools)
6. [Dynamic Analysis Tools](#dynamic-analysis-tools)
7. [Network Analysis Tools](#network-analysis-tools)
8. [Environment Validation](#environment-validation)

## Flutter SDK Installation

### Prerequisites
```bash
# Install Git
sudo apt-get update
sudo apt-get install git curl

# Install dependencies
sudo apt-get install -y unzip xz-utils zip libglu1-mesa
```

### Flutter SDK Setup
```bash
# Download Flutter SDK
cd ~/development
git clone https://github.com/flutter/flutter.git -b stable

# Add Flutter to PATH
export PATH="$PATH:`pwd`/flutter/bin"

# Verify installation
flutter doctor

# Install required plugins
flutter doctor --android-licenses
```

### Android Setup for Flutter Testing
```bash
# Install Android SDK
sudo apt-get install android-sdk

# Install Android Studio (recommended)
wget https://redirector.gvt1.com/edgedl/android/studio/ide-zips/2023.1.1.28/android-studio-2023.1.1.28-linux.tar.gz
tar -xf android-studio-*.tar.gz

# Set ANDROID_HOME
export ANDROID_HOME=$HOME/Android/Sdk
export PATH=$PATH:$ANDROID_HOME/tools
export PATH=$PATH:$ANDROID_HOME/platform-tools

# Verify Android setup
flutter doctor
```

## Development Environment Setup

### VS Code Configuration
```bash
# Install VS Code
sudo snap install code --classic

# Install Flutter extension
code --install-extension Dart-Code.flutter
code --install-extension Dart-Code.dart-code

# Install useful extensions for security testing
code --install-extension ms-vscode.hexdump
code --install-extension redhat.vscode-yaml
```

### Android Studio Configuration
```bash
# Install Flutter plugin
# File > Settings > Plugins > Browse repositories > Flutter

# Install Dart plugin
# Should be automatically installed with Flutter plugin

# Configure Android emulator
# Tools > AVD Manager > Create Virtual Device
```

## Security Testing Tools

### FRIDA for Flutter Testing
```bash
# Install FRIDA
pip3 install frida-tools

# Install FRIDA server on device
# Download frida-server from GitHub releases
# Push to device and set permissions
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server

# Start FRIDA server
adb shell su -c "/data/local/tmp/frida-server &"

# Verify FRIDA connection
frida-ps -U
```

### Proxy Tools for Flutter
```bash
# Install mitmproxy
pip3 install mitmproxy

# Install HTTP Toolkit (recommended for Flutter)
# Download from https://httptoolkit.tech/
wget https://github.com/httptoolkit/httptoolkit-desktop/releases/download/v1.15.1/HttpToolkit-1.15.1.AppImage
chmod +x HttpToolkit-1.15.1.AppImage

# Burp Suite Community Edition
# Download from https://portswigger.net/burp/communitydownload
```

## Flutter-Specific Tools

### Reify (Flutter Reverse Engineering)
```bash
# Install Reify
pip3 install reify

# Verify installation
reify --help

# Usage example
reify app-release.apk
reify --list-classes app-release.apk
```

### reflutter (Flutter Analysis Tool)
```bash
# Clone reflutter
git clone https://github.com/ptswarm/reflutter.git
cd reflutter

# Install dependencies
pip3 install -r requirements.txt

# Verify installation
python3 reflutter.py --help

# Usage example
python3 reflutter.py app-release.apk
```

### Flutter DevTools
```bash
# DevTools comes with Flutter SDK
# Launch with Flutter app
flutter run --debug

# Open DevTools in browser
# URL will be displayed in flutter run output
# Usually: http://localhost:9100
```

## Static Analysis Tools

### APK Analysis Tools
```bash
# Install APKTool
wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool
wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.8.1.jar
chmod +x apktool
sudo mv apktool /usr/local/bin/
sudo mv apktool_2.8.1.jar /usr/local/bin/apktool.jar

# Install JADX
wget https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip
unzip jadx-1.4.7.zip
sudo mv jadx-1.4.7 /opt/jadx
export PATH=$PATH:/opt/jadx/bin

# Install dex2jar
wget https://github.com/pxb1988/dex2jar/releases/download/v2.2/dex2jar-2.2.zip
unzip dex2jar-2.2.zip
sudo mv dex-tools-2.2 /opt/dex2jar
export PATH=$PATH:/opt/dex2jar
```

### Code Analysis Tools
```bash
# Install semgrep for security scanning
pip3 install semgrep

# Install bandit for Python code analysis
pip3 install bandit

# Install MobSF (Mobile Security Framework)
docker pull opensecurity/mobsf
# Or install from source
git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
cd Mobile-Security-Framework-MobSF
./setup.sh
```

## Dynamic Analysis Tools

### Flutter Inspector & Observatory
```bash
# Flutter Inspector (built into Flutter SDK)
flutter run --debug
# Open http://localhost:9100 in browser

# Dart Observatory (debugging)
flutter run --debug --observatory-port=8080
# Access via URL displayed in terminal
```

### Memory Analysis
```bash
# Install GDB for native debugging
sudo apt-get install gdb

# Install Volatility for memory analysis
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
pip3 install -r requirements.txt

# Install LIME for Android memory acquisition
git clone https://github.com/504ensicsLabs/LiME.git
```

### File System Analysis
```bash
# Install SQLite tools
sudo apt-get install sqlite3

# Install hexdump tools
sudo apt-get install bsdmainutils

# Install file analysis tools
sudo apt-get install file binutils
```

## Network Analysis Tools

### Traffic Interception
```bash
# Configure mitmproxy for Flutter
# Create mitmproxy addon for Flutter detection
cat > flutter_addon.py << 'EOF'
from mitmproxy import http
import json

class FlutterAddon:
    def request(self, flow: http.HTTPFlow) -> None:
        user_agent = flow.request.headers.get("user-agent", "")
        if "Dart/" in user_agent or "Flutter/" in user_agent:
            print(f"[Flutter] {flow.request.method} {flow.request.pretty_url}")
    
    def response(self, flow: http.HTTPFlow) -> None:
        user_agent = flow.request.headers.get("user-agent", "")
        if "Dart/" in user_agent or "Flutter/" in user_agent:
            print(f"[Flutter] Response: {flow.response.status_code}")

addons = [FlutterAddon()]
EOF

# Run mitmproxy with Flutter addon
mitmproxy -s flutter_addon.py
```

### SSL/TLS Analysis
```bash
# Install testssl.sh
git clone https://github.com/drwetter/testssl.sh.git
cd testssl.sh
chmod +x testssl.sh
sudo mv testssl.sh /usr/local/bin/

# Install sslscan
sudo apt-get install sslscan

# Install nmap for port scanning
sudo apt-get install nmap
```

## Environment Validation

### Validation Script
```bash
# Create validation script
cat > validate_flutter_env.sh << 'EOF'
#!/bin/bash

echo "=== Flutter Environment Validation ==="

# Check Flutter installation
echo -n "Flutter SDK: "
if command -v flutter &> /dev/null; then
    flutter --version | head -1
else
    echo "❌ Not installed"
fi

# Check Android SDK
echo -n "Android SDK: "
if [ -n "$ANDROID_HOME" ] && [ -d "$ANDROID_HOME" ]; then
    echo "✓ Installed at $ANDROID_HOME"
else
    echo "❌ Not configured"
fi

# Check ADB
echo -n "ADB: "
if command -v adb &> /dev/null; then
    echo "✓ $(adb version | head -1)"
else
    echo "❌ Not installed"
fi

# Check FRIDA
echo -n "FRIDA: "
if command -v frida &> /dev/null; then
    echo "✓ $(frida --version)"
else
    echo "❌ Not installed"
fi

# Check Python tools
echo -n "Reify: "
if command -v reify &> /dev/null; then
    echo "✓ Installed"
else
    echo "❌ Not installed"
fi

echo -n "mitmproxy: "
if command -v mitmproxy &> /dev/null; then
    echo "✓ $(mitmproxy --version | head -1)"
else
    echo "❌ Not installed"
fi

# Check static analysis tools
echo -n "APKTool: "
if command -v apktool &> /dev/null; then
    echo "✓ $(apktool --version | head -1)"
else
    echo "❌ Not installed"
fi

echo -n "JADX: "
if command -v jadx &> /dev/null; then
    echo "✓ Installed"
else
    echo "❌ Not installed"
fi

# Check device connectivity
echo -n "Device connectivity: "
device_count=$(adb devices | grep -c "device$")
if [ $device_count -gt 0 ]; then
    echo "✓ $device_count device(s) connected"
else
    echo "❌ No devices connected"
fi

echo "=== Validation Complete ==="
EOF

chmod +x validate_flutter_env.sh
./validate_flutter_env.sh
```

### Flutter Doctor Check
```bash
# Run comprehensive Flutter environment check
flutter doctor -v

# Check for any missing dependencies
flutter doctor --android-licenses

# Verify Flutter can create and build apps
flutter create test_app
cd test_app
flutter build apk --debug
cd ..
rm -rf test_app
```

### Testing Environment Setup
```bash
# Create a test Flutter app for security testing
flutter create flutter_security_test
cd flutter_security_test

# Add security testing dependencies to pubspec.yaml
cat >> pubspec.yaml << 'EOF'

  # Security testing dependencies
  dio: ^5.3.2
  http: ^1.1.0
  shared_preferences: ^2.2.1
  flutter_secure_storage: ^9.0.0

dev_dependencies:
  integration_test:
    sdk: flutter
EOF

# Install dependencies
flutter pub get

# Build for testing
flutter build apk --debug
flutter build apk --release

echo "Flutter security testing environment setup complete!"
```

## Usage Examples

### Basic Flutter App Analysis
```bash
# 1. Extract and analyze APK
apktool d app-release.apk
cd app-release

# 2. Analyze Flutter assets
ls assets/flutter_assets/
cat assets/flutter_assets/AssetManifest.json | jq '.'

# 3. Extract strings from Dart code
strings lib/arm64-v8a/libapp.so | grep -i "http\|api\|secret"

# 4. Run static analysis
reify ../app-release.apk
```

### Dynamic Testing Setup
```bash
# 1. Start FRIDA server on device
adb shell su -c "/data/local/tmp/frida-server &"

# 2. Install and run Flutter app
adb install app-release.apk
adb shell monkey -p com.example.app -c android.intent.category.LAUNCHER 1

# 3. Attach FRIDA script
frida -U -l flutter-ssl-pinning-bypass.js com.example.app

# 4. Start network monitoring
mitmproxy -s flutter_addon.py
```

---

This setup guide provides a comprehensive environment for Flutter application security testing. Ensure all tools are properly configured before beginning security assessments.