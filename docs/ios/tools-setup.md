# iOS Security Testing Tools Setup Guide

## Table of Contents
1. [Development Environment](#development-environment)
2. [Essential Tools](#essential-tools)
3. [Jailbreak Tools](#jailbreak-tools)
4. [Static Analysis Tools](#static-analysis-tools)
5. [Dynamic Analysis Tools](#dynamic-analysis-tools)
6. [Network Analysis Tools](#network-analysis-tools)
7. [Specialized iOS Tools](#specialized-ios-tools)

## Development Environment

### Prerequisites
- **macOS** (required for iOS development)
- **Xcode** (latest version from App Store)
- **iOS device** (physical device recommended)
- **Apple Developer Account** (for device provisioning)

### Xcode Setup
```bash
# Install Xcode from App Store
# Install Xcode Command Line Tools
xcode-select --install

# Verify installation
xcode-select -p
xcrun --version
```

### Homebrew Installation
```bash
# Install Homebrew package manager
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Update Homebrew
brew update
brew upgrade
```

## Essential Tools

### 1. **libimobiledevice**
```bash
# Install libimobiledevice suite
brew install libimobiledevice

# Available tools:
idevice_id          # List connected devices
ideviceinfo         # Device information
idevicesyslog       # System log access
ideviceinstaller    # App installation
idevicebackup2      # Device backup/restore
idevicescreenshot   # Screenshots
```

#### Usage Examples:
```bash
# List connected devices
idevice_id -l

# Get device information
ideviceinfo -k DeviceName
ideviceinfo -k ProductVersion

# Monitor system logs
idevicesyslog

# Install IPA file
ideviceinstaller -i app.ipa

# Take screenshot
idevicescreenshot screenshot.png
```

### 2. **ios-deploy**
```bash
# Install ios-deploy
brew install ios-deploy

# Usage examples:
ios-deploy --list                    # List devices
ios-deploy --bundle app.app          # Install app
ios-deploy --debug --bundle app.app  # Install and debug
```

### 3. **USB Multiplexer (usbmuxd)**
```bash
# Install usbmuxd for USB communication
brew install usbmuxd

# Port forwarding for SSH (jailbroken devices)
iproxy 2222 22 &

# SSH into device
ssh root@localhost -p 2222
```

## Jailbreak Tools

### Current Jailbreak Status (2024)

#### checkra1n (Hardware-based)
- **Supported**: iPhone 5s - iPhone X (A7-A11 chips)
- **iOS Versions**: 12.0 - 14.8.1
- **Type**: Semi-tethered
- **Website**: https://checkra.in/

```bash
# Download and run checkra1n
# Follow on-screen instructions
# Requires DFU mode entry
```

#### unc0ver
- **Supported**: Various devices
- **iOS Versions**: 11.0 - 14.8
- **Type**: Semi-untethered
- **Website**: https://unc0ver.dev/

#### Odyssey/Taurine
- **Supported**: A12-A14 devices
- **iOS Versions**: 13.0 - 14.3
- **Type**: Semi-untethered
- **Website**: https://taurine.app/

### Post-Jailbreak Setup
```bash
# SSH into jailbroken device
ssh root@<device-ip>

# Change default password (IMPORTANT!)
passwd

# Update package sources
apt-get update

# Install essential packages
apt-get install wget curl vim nano openssh
```

## Static Analysis Tools

### 1. **class-dump**
```bash
# Install class-dump
brew install class-dump

# Extract Objective-C headers from Mach-O files
class-dump -H /path/to/binary > headers.h

# Dump specific class
class-dump -f ClassName /path/to/binary

# Include private frameworks
class-dump -H /System/Library/PrivateFrameworks/MobileActivation.framework/MobileActivation
```

### 2. **otool (Part of Xcode)**
```bash
# Display shared libraries
otool -L /path/to/binary

# Display Mach-O header
otool -h /path/to/binary

# Display load commands
otool -l /path/to/binary

# Display strings section
otool -s __TEXT __cstring /path/to/binary

# Check security features
otool -hv /path/to/binary | grep PIE    # ASLR support
otool -hv /path/to/binary | grep STACK  # Stack protection
```

### 3. **strings**
```bash
# Extract strings from binary
strings /path/to/binary

# Search for specific patterns
strings /path/to/binary | grep -i "password\|secret\|api"
strings /path/to/binary | grep -E "https?://"
```

### 4. **plutil**
```bash
# Convert and display plist files
plutil -p Info.plist

# Convert binary plist to XML
plutil -convert xml1 binary.plist -o readable.plist

# Validate plist syntax
plutil -lint Info.plist
```

### 5. **Hopper Disassembler**
```bash
# Commercial disassembler (alternative to IDA Pro)
# Download from: https://www.hopperapp.com/
# Excellent ARM64 support
# Good for reverse engineering
```

### 6. **Ghidra**
```bash
# Free NSA reverse engineering tool
# Download from: https://ghidra-sre.org/
# Cross-platform
# Excellent decompilation capabilities
```

## Dynamic Analysis Tools

### 1. **FRIDA**
```bash
# Install FRIDA
pip3 install frida-tools

# Verify installation
frida --version

# List processes on device
frida-ps -H <device-ip>

# Run script on target app
frida -H <device-ip> -l script.js com.example.app
```

### 2. **LLDB (Low Level Debugger)**
```bash
# Attach to running process
lldb -p $(pgrep -f "YourApp")

# Basic LLDB commands
(lldb) process attach --pid <pid>
(lldb) br set -n objc_msgSend
(lldb) c                    # continue
(lldb) bt                   # backtrace
(lldb) po $arg1            # print object
```

### 3. **Instruments**
```bash
# Launch Instruments (part of Xcode)
instruments

# Common templates:
# - Time Profiler: CPU usage analysis
# - Allocations: Memory usage
# - Leaks: Memory leak detection
# - Network: Network activity
# - System Trace: System calls

# Command line usage
instruments -t "Time Profiler" -D trace.trace YourApp.app
```

### 4. **Console.app**
```bash
# Monitor iOS device logs
# Applications > Utilities > Console.app
# Connect iOS device
# Filter by device and process
```

### 5. **Keychain-Dumper**
```bash
# Download keychain-dumper (requires jailbreak)
git clone https://github.com/ptoomey3/Keychain-Dumper
cd Keychain-Dumper
make

# Copy to iOS device
scp keychain_dumper root@<device-ip>:/tmp/

# Run on device
ssh root@<device-ip>
/tmp/keychain_dumper > keychain_data.txt
```

## Network Analysis Tools

### 1. **Burp Suite**
```bash
# Professional Edition recommended
# Download from: https://portswigger.net/burp

# Setup steps:
# 1. Configure Burp to listen on all interfaces
# 2. Configure iOS device proxy settings
# 3. Install Burp CA certificate on device
# 4. Trust certificate in Settings > General > About > Certificate Trust Settings
```

### 2. **OWASP ZAP**
```bash
# Free alternative to Burp Suite
# Download from: https://www.zaproxy.org/

# Docker installation
docker run -t owasp/zap2docker-stable zap-baseline.py -t http://target-app
```

### 3. **mitmproxy**
```bash
# Install mitmproxy
brew install mitmproxy

# Start proxy
mitmdump -s script.py

# Web interface
mitmweb
```

### 4. **Wireshark**
```bash
# Install Wireshark
brew install --cask wireshark

# Capture traffic
# Use with remote capture setup for iOS devices
```

## Specialized iOS Tools

### 1. **Clutch** (App Decryption)
```bash
# Requires jailbroken device
# Download from: https://github.com/KJCracks/Clutch

# Install on device
scp Clutch root@<device-ip>:/usr/bin/
ssh root@<device-ip> chmod +x /usr/bin/Clutch

# Decrypt applications
Clutch -i                    # List installed apps
Clutch -d "App Name"         # Decrypt specific app
```

### 2. **dump-decrypted**
```bash
# Alternative decryption tool
# Download from: https://github.com/stefanesser/dumpdecrypted

# Compile and install
make
scp dumpdecrypted.dylib root@<device-ip>:/usr/lib/

# Usage with DYLD_INSERT_LIBRARIES
DYLD_INSERT_LIBRARIES=/usr/lib/dumpdecrypted.dylib /var/containers/Bundle/Application/<UUID>/YourApp.app/YourApp
```

### 3. **SSL Kill Switch 2**
```bash
# Install via Cydia
# Repository: https://github.com/nabla-c0d3/ssl-kill-switch2

# Toggle SSL pinning bypass in Settings
# Works with most iOS apps
```

### 4. **Cycript**
```bash
# Runtime manipulation tool (deprecated but still useful)
# Install via Cydia on jailbroken device

# Usage
cycript -p YourApp
cy# [UIApplication sharedApplication]
```

### 5. **iMazing**
```bash
# Commercial iOS device management tool
# Download from: https://imazing.com/

# Features:
# - App data extraction
# - Backup analysis
# - File system access (with jailbreak)
```

### 6. **3uTools**
```bash
# Free iOS device management
# Download from: http://www.3u.com/

# Features:
# - File management
# - App installation
# - System information
```

## Tool Configuration Examples

### 1. **FRIDA Setup for iOS**
```bash
# Install FRIDA on iOS device (jailbroken)
# Add repository: https://build.frida.re
# Install "FRIDA" package from Cydia

# Test connection
frida-ps -H <device-ip>

# Run script
frida -H <device-ip> -l bypass.js com.example.app
```

### 2. **Burp Suite Certificate Installation**
```bash
# Steps:
# 1. Go to burp in mobile browser
# 2. Download cacert.der
# 3. Settings > General > Profiles & Device Management
# 4. Install profile
# 5. Settings > General > About > Certificate Trust Settings
# 6. Enable full trust for Burp certificate
```

### 3. **SSH Configuration**
```bash
# Generate SSH key pair
ssh-keygen -t rsa -b 4096 -C "ios-testing"

# Copy public key to device
ssh-copy-id root@<device-ip>

# SSH config for convenience
cat >> ~/.ssh/config << EOF
Host ios-device
    HostName <device-ip>
    User root
    Port 22
    IdentityFile ~/.ssh/id_rsa
EOF

# Connect easily
ssh ios-device
```

## Automation Scripts

### 1. **Device Setup Script**
```bash
#!/bin/bash
# iOS device setup automation

DEVICE_IP=$1

if [ -z "$DEVICE_IP" ]; then
    echo "Usage: $0 <device-ip>"
    exit 1
fi

echo "[*] Setting up iOS device at $DEVICE_IP"

# Test SSH connection
ssh -o ConnectTimeout=5 root@$DEVICE_IP "echo 'SSH connection successful'"

# Update package sources
ssh root@$DEVICE_IP "apt-get update"

# Install essential packages
ssh root@$DEVICE_IP "apt-get install -y wget curl vim nano"

# Install useful tools
ssh root@$DEVICE_IP "wget https://github.com/ptoomey3/Keychain-Dumper/raw/master/keychain_dumper -O /usr/bin/keychain_dumper"
ssh root@$DEVICE_IP "chmod +x /usr/bin/keychain_dumper"

echo "[+] Device setup complete"
```

### 2. **App Analysis Script**
```bash
#!/bin/bash
# iOS app analysis automation

APP_NAME=$1
DEVICE_IP=$2

if [ -z "$APP_NAME" ] || [ -z "$DEVICE_IP" ]; then
    echo "Usage: $0 <app-bundle-id> <device-ip>"
    exit 1
fi

echo "[*] Analyzing $APP_NAME on device $DEVICE_IP"

# Get app information
frida-ps -H $DEVICE_IP -ai | grep -i "$APP_NAME"

# Run basic FRIDA script
frida -H $DEVICE_IP -l ios-basic-info.js "$APP_NAME"

echo "[+] Analysis complete"
```

## Troubleshooting

### Common Issues:

1. **Device Not Recognized**
```bash
# Check device connection
idevice_id -l

# Restart usbmuxd
sudo launchctl unload /System/Library/LaunchDaemons/com.apple.usbmuxd.plist
sudo launchctl load /System/Library/LaunchDaemons/com.apple.usbmuxd.plist
```

2. **SSH Connection Fails**
```bash
# Check device IP
ideviceinfo -k WiFiAddress

# Test network connectivity
ping <device-ip>

# Check SSH service on device
ssh root@<device-ip> "ps aux | grep sshd"
```

3. **FRIDA Connection Issues**
```bash
# Check FRIDA server on device
ssh root@<device-ip> "ps aux | grep frida-server"

# Restart FRIDA server
ssh root@<device-ip> "killall frida-server"
ssh root@<device-ip> "frida-server &"
```

4. **Certificate Trust Issues**
```bash
# Ensure certificate is trusted
# Settings > General > About > Certificate Trust Settings
# Enable full trust for root certificates
```

## Security Considerations

### Testing Safety:
- Use dedicated test devices
- Backup devices before jailbreaking
- Test in isolated network environment
- Be aware of warranty implications

### Legal Compliance:
- Only test apps you own or have authorization to test
- Respect intellectual property rights
- Follow responsible disclosure practices
- Comply with local laws and regulations

---

This setup guide provides a comprehensive foundation for iOS security testing. Combine these tools with the methodologies in the main iOS documentation for effective security assessments.