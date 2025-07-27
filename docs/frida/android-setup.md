# FRIDA Setup Guide for Android

## Prerequisites

### Requirements:
- Python 3.7 or higher
- Android device with USB debugging enabled
- ADB (Android Debug Bridge) installed
- Root access on Android device (recommended)

### Check Android Architecture:
```bash
adb shell getprop ro.product.cpu.abi
# Common outputs: arm64-v8a, armeabi-v7a, x86, x86_64
```

## Installation Steps

### Step 1: Install FRIDA Client Tools
```bash
# Update pip
python -m pip install --upgrade pip

# Install FRIDA tools
pip install frida-tools

# Verify installation
frida --version
frida-ps --version
```

### Step 2: Download FRIDA Server
```bash
# Check latest version at: https://github.com/frida/frida/releases
FRIDA_VERSION="16.1.4"
ANDROID_ARCH="arm64"  # Change based on your device

# Download frida-server
wget https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-${ANDROID_ARCH}.xz

# Extract the file
unxz frida-server-${FRIDA_VERSION}-android-${ANDROID_ARCH}.xz
mv frida-server-${FRIDA_VERSION}-android-${ANDROID_ARCH} frida-server
```

### Step 3: Deploy FRIDA Server to Android Device
```bash
# Push frida-server to device
adb push frida-server /data/local/tmp/

# Make it executable
adb shell chmod 755 /data/local/tmp/frida-server

# Start frida-server (requires root)
adb shell su -c "/data/local/tmp/frida-server &"
```

### Step 4: Setup Port Forwarding
```bash
# Forward the default FRIDA port
adb forward tcp:27042 tcp:27042

# Verify connection
frida-ps -U
```

## Non-Root Setup (Limited Functionality)

### For devices without root access:
```bash
# Use frida-server in app context (limited)
# Some operations won't work without root

# Alternative: Use Magisk with frida-server module
# Or use rooted emulator for testing
```

## Testing Installation

### Basic Connectivity Test:
```bash
# List running processes
frida-ps -U

# List installed applications
frida-ps -Uai

# Test with simple script
frida -U -l test-script.js com.example.app
```

### Sample Test Script (test-script.js):
```javascript
console.log("[*] FRIDA connection successful!");

Java.perform(function() {
    console.log("[*] Java runtime available");
    
    // List loaded classes (limited output)
    Java.enumerateLoadedClasses({
        onMatch: function(name, handle) {
            if (name.includes("MainActivity")) {
                console.log("[*] Found MainActivity: " + name);
            }
        },
        onComplete: function() {
            console.log("[*] Class enumeration complete");
        }
    });
});
```

## Common Android Targets

### System Applications:
```bash
# Settings app
frida -U com.android.settings

# Chrome browser
frida -U com.android.chrome

# Phone dialer
frida -U com.android.dialer
```

### Package Information:
```bash
# Get package info
adb shell pm list packages | grep <app_name>
adb shell pm dump <package_name>

# Get APK path
adb shell pm path <package_name>
```

## Troubleshooting

### Common Issues:

1. **"Unable to connect to remote frida-server"**
   ```bash
   # Check if frida-server is running
   adb shell ps | grep frida-server
   
   # Restart frida-server
   adb shell su -c "killall frida-server"
   adb shell su -c "/data/local/tmp/frida-server &"
   ```

2. **Architecture Mismatch**
   ```bash
   # Verify device architecture
   adb shell getprop ro.product.cpu.abi
   
   # Download correct frida-server version
   ```

3. **Permission Denied**
   ```bash
   # Ensure device is rooted
   adb shell su -c "whoami"
   
   # Check SELinux status
   adb shell getenforce
   ```

4. **Port Already in Use**
   ```bash
   # Kill existing port forwards
   adb forward --remove-all
   
   # Use different port
   adb forward tcp:27043 tcp:27042
   frida -H 127.0.0.1:27043 -l script.js com.example.app
   ```

## Advanced Configuration

### Persistent FRIDA Server:
```bash
# Create systemd-style service (requires root)
adb shell su -c "cat > /system/etc/init.d/frida-server << 'EOF'
#!/system/bin/sh
/data/local/tmp/frida-server &
EOF"

adb shell su -c "chmod 755 /system/etc/init.d/frida-server"
```

### Network Access:
```bash
# Run frida-server with network binding
adb shell su -c "/data/local/tmp/frida-server -l 0.0.0.0:27042 &"

# Connect from remote machine
frida -H <device_ip>:27042 -l script.js com.example.app
```

### Multiple Devices:
```bash
# List connected devices
adb devices

# Target specific device
frida -D <device_id> -l script.js com.example.app
```

## Security Considerations

### Bypassing Anti-FRIDA:
- Some apps detect FRIDA presence
- Use renamed frida-server binary
- Modify FRIDA signatures
- Use custom builds

### Safe Testing:
- Always test on dedicated devices
- Backup important data
- Use emulators for initial testing
- Be aware of app store policies

## Next Steps

1. Try basic hooking examples in `/frida-scripts/android/`
2. Practice with vulnerable apps in `/Applications/`
3. Read advanced FRIDA documentation
4. Join FRIDA community forums for support