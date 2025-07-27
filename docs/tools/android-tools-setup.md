# Android Security Testing Tools Setup Guide

## Table of Contents
1. [Development Environment](#development-environment)
2. [Device Setup](#device-setup)
3. [Static Analysis Tools](#static-analysis-tools)
4. [Dynamic Analysis Tools](#dynamic-analysis-tools)
5. [Network Analysis Tools](#network-analysis-tools)
6. [Specialized Android Tools](#specialized-android-tools)
7. [Automation and CI/CD](#automation-and-cicd)

## Development Environment

### Prerequisites
- **Operating System**: Linux (Ubuntu/Kali), macOS, or Windows with WSL
- **Java Development Kit**: JDK 8 or higher
- **Python**: Python 3.7+ with pip
- **Git**: For tool installation and updates

### Android SDK Setup
```bash
# Download Android SDK
wget https://dl.google.com/android/repository/commandlinetools-linux-latest.zip
unzip commandlinetools-linux-latest.zip -d ~/android-sdk

# Set environment variables
echo 'export ANDROID_HOME=~/android-sdk' >> ~/.bashrc
echo 'export PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools' >> ~/.bashrc
source ~/.bashrc

# Install SDK components
sdkmanager "platform-tools" "platforms;android-30" "build-tools;30.0.3"

# Verify installation
adb version
```

### Java Environment
```bash
# Install OpenJDK (Ubuntu/Debian)
sudo apt update
sudo apt install openjdk-11-jdk

# Set JAVA_HOME
echo 'export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64' >> ~/.bashrc
source ~/.bashrc

# Verify installation
java -version
javac -version
```

## Device Setup

### Physical Device Configuration

#### Enable Developer Options:
1. Go to **Settings > About Phone**
2. Tap **Build Number** 7 times
3. Navigate to **Settings > Developer Options**
4. Enable **USB Debugging**
5. Enable **Stay Awake** (optional)

#### Security Settings:
```bash
# Verify device connection
adb devices

# Check device info
adb shell getprop ro.build.version.release  # Android version
adb shell getprop ro.product.cpu.abi        # Architecture
adb shell getprop ro.secure                 # Security status
adb shell getprop ro.debuggable             # Debug status
```

### Emulator Setup
```bash
# Install Android Studio (includes emulator)
# Or use command line tools

# Create AVD (Android Virtual Device)
avdmanager create avd -n SecurityTest -k "system-images;android-30;google_apis;x86_64"

# Start emulator
emulator -avd SecurityTest -no-snapshot-save -wipe-data

# Configure emulator for testing
adb shell settings put global window_animation_scale 0
adb shell settings put global transition_animation_scale 0
adb shell settings put global animator_duration_scale 0
```

### Root Access Setup

#### Magisk (Recommended for modern devices):
```bash
# Download Magisk Manager APK
# Install via ADB
adb install Magisk-v24.3.apk

# Follow device-specific rooting instructions
# This varies by manufacturer and model
```

#### Alternative Methods:
- **SuperSU**: Legacy rooting solution
- **LineageOS**: Custom ROM with root access
- **Rooted Emulator**: Pre-rooted Android x86 images

## Static Analysis Tools

### 1. **APKTool**
```bash
# Download APKTool
wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool
wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.7.0.jar -O apktool.jar

# Make executable
chmod +x apktool
chmod +x apktool.jar

# Move to PATH
sudo mv apktool /usr/local/bin/
sudo mv apktool.jar /usr/local/bin/

# Test installation
apktool version
```

**Usage Examples:**
```bash
# Decompile APK
apktool d app.apk

# Rebuild APK
apktool b app/

# Install framework files
apktool if framework-res.apk
```

### 2. **JADX**
```bash
# Download JADX
wget https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip
unzip jadx-1.4.7.zip -d ~/tools/jadx

# Add to PATH
echo 'export PATH=$PATH:~/tools/jadx/bin' >> ~/.bashrc
source ~/.bashrc

# Test installation
jadx --version
```

**Usage Examples:**
```bash
# GUI mode
jadx-gui app.apk

# Command line
jadx -d output_dir app.apk

# Export to single file
jadx --export-gradle app.apk
```

### 3. **MobSF (Mobile Security Framework)**
```bash
# Install dependencies
sudo apt install python3-dev python3-venv python3-pip build-essential libffi-dev libssl-dev libxml2-dev libxslt1-dev libjpeg8-dev zlib1g-dev wkhtmltopdf

# Clone repository
git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
cd Mobile-Security-Framework-MobSF

# Install Python dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run MobSF
python manage.py runserver 127.0.0.1:8000
```

**Docker Installation (Alternative):**
```bash
# Pull Docker image
docker pull opensecurity/mobsf

# Run container
docker run -it -p 8000:8000 opensecurity/mobsf:latest

# Access via browser: http://localhost:8000
```

### 4. **QARK (Quick Android Review Kit)**
```bash
# Install QARK
pip install qark

# Run analysis
qark --apk path/to/app.apk --report-type html

# Generate JSON report
qark --apk path/to/app.apk --report-type json
```

### 5. **Semgrep**
```bash
# Install Semgrep
pip install semgrep

# Run Android-specific rules
semgrep --config=p/android-security path/to/source/

# Custom rules
semgrep --config=custom-android-rules.yml path/to/source/
```

## Dynamic Analysis Tools

### 1. **FRIDA**
```bash
# Install FRIDA
pip install frida-tools

# Download frida-server for Android
FRIDA_VERSION="16.1.4"
ARCH="arm64"  # or arm, x86, x86_64

wget https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-${ARCH}.xz

# Extract and deploy
unxz frida-server-${FRIDA_VERSION}-android-${ARCH}.xz
adb push frida-server-${FRIDA_VERSION}-android-${ARCH} /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server

# Start frida-server (requires root)
adb shell su -c "/data/local/tmp/frida-server &"

# Test connection
frida-ps -U
```

### 2. **Xposed Framework**
```bash
# Requirements: Rooted device
# Download Xposed Installer APK
adb install XposedInstaller.apk

# Follow in-app installation instructions
# Reboot device after installation

# Install useful modules:
# - SSL Pinning Bypass
# - Root Cloak
# - App Settings
```

### 3. **Drozer**
```bash
# Install dependencies
sudo apt install python2.7 python-pip

# Install Drozer
pip install drozer

# Install Drozer agent on device
adb install drozer-agent.apk

# Forward port
adb forward tcp:31415 tcp:31415

# Connect to device
drozer console connect
```

**Usage Examples:**
```bash
# List packages
run app.package.list

# Get package info
run app.package.info -a com.example.app

# Check attack surface
run app.package.attacksurface com.example.app

# Test content providers
run app.provider.info -a com.example.app
run scanner.provider.finduris -a com.example.app
```

### 4. **Objection**
```bash
# Install Objection
pip install objection

# Patch APK for runtime manipulation
objection patchapk --source app.apk

# Install patched APK
adb install app.objection.apk

# Connect to app
objection explore

# Common commands
android hooking list classes
android hooking search methods <pattern>
android intent launch_activity <activity>
android keystore list
```

## Network Analysis Tools

### 1. **Burp Suite**
```bash
# Download Burp Suite Community/Professional
# Configure proxy settings

# Generate CA certificate
# Export certificate from Burp

# Install on Android device
adb push cacert.der /sdcard/
# Settings > Security > Install from storage

# Configure device proxy
# Settings > WiFi > Advanced > Proxy > Manual
# Host: <burp-ip>, Port: 8080
```

### 2. **OWASP ZAP**
```bash
# Install ZAP
sudo apt install zaproxy

# Or download from official site
wget https://github.com/zaproxy/zaproxy/releases/download/v2.12.0/ZAP_2.12.0_Linux.tar.gz

# Run ZAP
zaproxy

# Configure proxy (similar to Burp Suite)
```

### 3. **mitmproxy**
```bash
# Install mitmproxy
pip install mitmproxy

# Start proxy
mitmdump -s custom_script.py

# Web interface
mitmweb --web-port 8081

# Install certificate on device
# Download from http://mitm.it when connected to proxy
```

## Specialized Android Tools

### 1. **ADB (Android Debug Bridge)**
```bash
# Essential ADB commands for security testing

# Install APK
adb install app.apk
adb install -r app.apk  # Reinstall

# Uninstall APK
adb uninstall com.example.app

# File operations
adb push local_file /data/local/tmp/
adb pull /data/local/tmp/remote_file ./

# Shell access
adb shell
adb shell su  # Root shell

# Log monitoring
adb logcat
adb logcat | grep "com.example.app"

# Screen capture
adb exec-out screencap -p > screenshot.png

# Port forwarding
adb forward tcp:8080 tcp:8080
```

### 2. **dex2jar**
```bash
# Download dex2jar
wget https://github.com/pxb1988/dex2jar/releases/download/v2.1/dex-tools-2.1.zip
unzip dex-tools-2.1.zip -d ~/tools/

# Add to PATH
echo 'export PATH=$PATH:~/tools/dex-tools-2.1' >> ~/.bashrc
source ~/.bashrc

# Convert DEX to JAR
d2j-dex2jar.sh app.apk

# Decompile JAR with JD-GUI
java -jar jd-gui.jar app-dex2jar.jar
```

### 3. **Smali/Baksmali**
```bash
# Download smali tools
wget https://github.com/JesusFreke/smali/releases/download/v2.5.2/smali-2.5.2.jar
wget https://github.com/JesusFreke/smali/releases/download/v2.5.2/baksmali-2.5.2.jar

# Disassemble DEX
java -jar baksmali-2.5.2.jar d classes.dex

# Assemble smali to DEX
java -jar smali-2.5.2.jar a smali_output/
```

### 4. **Androguard**
```bash
# Install Androguard
pip install androguard

# Python usage
from androguard.misc import AnalyzeAPK

a, d, dx = AnalyzeAPK("app.apk")

# Get package name
print(a.get_package())

# Get activities
print(a.get_activities())

# Get permissions
print(a.get_permissions())
```

### 5. **Android Asset Packaging Tool (AAPT)**
```bash
# Comes with Android SDK

# Dump APK information
aapt dump badging app.apk
aapt dump permissions app.apk
aapt dump configurations app.apk

# List APK contents
aapt list app.apk

# Extract manifest
aapt dump xmltree app.apk AndroidManifest.xml
```

## Automation and CI/CD

### 1. **Docker Security Testing**
```bash
# Create Dockerfile for testing environment
cat > Dockerfile << 'EOF'
FROM ubuntu:20.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    openjdk-11-jdk \
    python3 \
    python3-pip \
    wget \
    unzip

# Install Android tools
RUN pip3 install frida-tools mobsf-python

# Add tools
COPY tools/ /opt/tools/
ENV PATH="/opt/tools:${PATH}"

CMD ["/bin/bash"]
EOF

# Build image
docker build -t android-security-testing .

# Run container
docker run -it --privileged -v $(pwd):/workspace android-security-testing
```

### 2. **Automated Testing Scripts**
```bash
#!/bin/bash
# automated-security-test.sh

APK_FILE=$1
OUTPUT_DIR="security_results"

if [ -z "$APK_FILE" ]; then
    echo "Usage: $0 <apk_file>"
    exit 1
fi

mkdir -p $OUTPUT_DIR

echo "[*] Starting automated security testing for $APK_FILE"

# Static analysis with MobSF
echo "[*] Running MobSF analysis..."
mobsf-python -f $APK_FILE -o $OUTPUT_DIR/mobsf_report.json

# APK analysis with APKTool
echo "[*] Decompiling with APKTool..."
apktool d $APK_FILE -o $OUTPUT_DIR/apktool_output

# Jadx decompilation
echo "[*] Decompiling with JADX..."
jadx -d $OUTPUT_DIR/jadx_output $APK_FILE

# Search for secrets
echo "[*] Searching for hardcoded secrets..."
grep -r -i "password\|secret\|key\|token" $OUTPUT_DIR/jadx_output/ > $OUTPUT_DIR/secrets.txt

# Manifest analysis
echo "[*] Analyzing manifest..."
aapt dump xmltree $APK_FILE AndroidManifest.xml > $OUTPUT_DIR/manifest.xml

echo "[*] Security testing complete. Results in $OUTPUT_DIR/"
```

### 3. **GitHub Actions Workflow**
```yaml
# .github/workflows/android-security.yml
name: Android Security Testing

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security-test:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Set up JDK 11
      uses: actions/setup-java@v2
      with:
        java-version: '11'
        distribution: 'adopt'
    
    - name: Install security tools
      run: |
        pip install mobsf-python
        wget https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip
        unzip jadx-1.4.7.zip
    
    - name: Run security analysis
      run: |
        ./scripts/automated-security-test.sh app.apk
    
    - name: Upload results
      uses: actions/upload-artifact@v2
      with:
        name: security-results
        path: security_results/
```

## Troubleshooting

### Common Issues:

1. **ADB Device Not Recognized**
```bash
# Check USB debugging
adb devices

# Restart ADB server
adb kill-server
adb start-server

# Check drivers (Windows)
# Install proper USB drivers for device
```

2. **FRIDA Connection Issues**
```bash
# Check frida-server is running
adb shell ps | grep frida-server

# Restart frida-server
adb shell su -c "killall frida-server"
adb shell su -c "/data/local/tmp/frida-server &"

# Check architecture compatibility
adb shell getprop ro.product.cpu.abi
```

3. **Burp Certificate Issues**
```bash
# Android 7+ certificate pinning
# Install certificate as system certificate (requires root)
adb shell
mount -o rw,remount /system
cp /sdcard/cacert.der /system/etc/security/cacerts/
chmod 644 /system/etc/security/cacerts/cacert.der
reboot
```

4. **Permission Denied Errors**
```bash
# Check file permissions
ls -la /data/local/tmp/

# Fix permissions
adb shell chmod 755 /data/local/tmp/frida-server

# Check SELinux status
adb shell getenforce
```

## Security Considerations

### Testing Environment:
- Use dedicated testing devices
- Isolate testing network
- Regular backup of testing environment
- Keep tools updated

### Legal and Ethical:
- Only test applications you own or have authorization to test
- Respect intellectual property rights
- Follow responsible disclosure practices
- Comply with local laws and regulations

---

This setup guide provides a comprehensive foundation for Android security testing. Adapt the tools and configurations based on your specific testing requirements and target applications.