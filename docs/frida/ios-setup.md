# FRIDA Setup Guide for iOS

## Prerequisites

### Requirements:
- macOS computer (for iOS development tools)
- Python 3.7 or higher
- Xcode and iOS development tools
- Jailbroken iOS device (for full functionality)
- SSH access to iOS device

### Supported iOS Versions:
- iOS 12.0 - iOS 16.x (varies by jailbreak availability)
- Check current jailbreak status at: [The iPhone Wiki](https://www.theiphonewiki.com/wiki/Jailbreak)

## Installation Steps

### Step 1: Install FRIDA Client Tools
```bash
# Update pip
python3 -m pip install --upgrade pip

# Install FRIDA tools
pip3 install frida-tools

# Verify installation
frida --version
frida-ps --version
```

### Step 2: Jailbreak Your iOS Device

#### Popular Jailbreaks (as of 2024):
- **checkra1n**: iOS 12.0-14.8.1 (A5-A11 devices)
- **unc0ver**: iOS 11.0-14.8
- **Taurine**: iOS 14.0-14.3
- **Odyssey**: iOS 13.0-13.7

#### Warning:
⚠️ Jailbreaking voids warranty and may cause security risks. Only jailbreak devices dedicated to security testing.

### Step 3: Install FRIDA on iOS Device

#### Method 1: Cydia Installation (Recommended)
```bash
# Add FRIDA repository in Cydia
# Repository URL: https://build.frida.re

# Install "FRIDA" package from Cydia
# This installs frida-server automatically
```

#### Method 2: Manual Installation
```bash
# SSH into your iOS device
ssh root@<device-ip>

# Download frida-server for iOS
wget https://github.com/frida/frida/releases/download/16.1.4/frida-server-16.1.4-ios-arm64.xz

# Extract and install
unxz frida-server-16.1.4-ios-arm64.xz
mv frida-server-16.1.4-ios-arm64 /usr/sbin/frida-server
chmod +x /usr/sbin/frida-server

# Create launchd plist for auto-start
cat > /Library/LaunchDaemons/re.frida.server.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>re.frida.server</string>
    <key>Program</key>
    <string>/usr/sbin/frida-server</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/sbin/frida-server</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF

# Start the service
launchctl load /Library/LaunchDaemons/re.frida.server.plist
```

### Step 4: Setup Network Connection

#### WiFi Connection (Recommended):
```bash
# Find device IP address
# Settings > WiFi > Your Network > (i) icon

# Test connection
frida-ps -H <device-ip>

# Run script
frida -H <device-ip> -l script.js com.apple.mobilesafari
```

#### USB Connection:
```bash
# Install usbmuxd (macOS)
brew install usbmuxd

# Setup USB forwarding
iproxy 27042 27042 &

# Connect via localhost
frida-ps -H 127.0.0.1:27042
```

## Testing Installation

### Basic Connectivity Test:
```bash
# List running processes
frida-ps -H <device-ip>

# List installed applications
frida-ps -H <device-ip> -ai

# Test with Safari
frida -H <device-ip> com.apple.mobilesafari
```

### Sample Test Script (ios-test.js):
```javascript
console.log("[*] FRIDA iOS connection successful!");

// Test Objective-C runtime
if (ObjC.available) {
    console.log("[*] Objective-C runtime available");
    
    // List some classes
    for (var className in ObjC.classes) {
        if (className.includes("ViewController")) {
            console.log("[*] Found ViewController: " + className);
            break;
        }
    }
    
    // Hook a common method
    var NSString = ObjC.classes.NSString;
    if (NSString) {
        console.log("[*] NSString class found");
    }
} else {
    console.log("[!] Objective-C runtime not available");
}
```

## Common iOS Targets

### System Applications:
```bash
# Safari browser
frida -H <device-ip> com.apple.mobilesafari

# Settings app
frida -H <device-ip> com.apple.Preferences

# Messages app
frida -H <device-ip> com.apple.MobileSMS

# Photos app
frida -H <device-ip> com.apple.mobileslideshow
```

### Third-Party Apps:
```bash
# Instagram
frida -H <device-ip> com.burbn.instagram

# WhatsApp
frida -H <device-ip> net.whatsapp.WhatsApp

# Telegram
frida -H <device-ip> ph.telegra.Telegraph
```

### Finding Bundle Identifiers:
```bash
# SSH into device and list installed apps
ssh root@<device-ip>
ls /var/containers/Bundle/Application/

# Or use FRIDA
frida-ps -H <device-ip> -ai | grep -i <app_name>
```

## iOS-Specific Features

### Objective-C Method Hooking:
```javascript
// Hook Objective-C method
var ViewController = ObjC.classes.ViewController;
var originalMethod = ViewController['- viewDidLoad'];

Interceptor.attach(originalMethod.implementation, {
    onEnter: function(args) {
        console.log("[*] viewDidLoad called");
        console.log("[*] self: " + new ObjC.Object(args[0]));
    }
});
```

### Swift Method Hooking:
```javascript
// Find Swift symbols
var symbols = Module.enumerateSymbols("YourApp");
symbols.forEach(function(symbol) {
    if (symbol.name.includes("Swift")) {
        console.log(symbol.name + " @ " + symbol.address);
    }
});
```

### Keychain Access:
```javascript
// Hook keychain operations
var SecItemCopyMatching = Module.findExportByName("Security", "SecItemCopyMatching");
Interceptor.attach(SecItemCopyMatching, {
    onEnter: function(args) {
        console.log("[*] SecItemCopyMatching called");
    },
    onLeave: function(retval) {
        console.log("[*] SecItemCopyMatching returned: " + retval);
    }
});
```

## Troubleshooting

### Common Issues:

1. **"Unable to connect to remote frida-server"**
   ```bash
   # Check if device is jailbroken
   ssh root@<device-ip> 'ls -la /Applications/Cydia.app'
   
   # Restart frida-server
   ssh root@<device-ip> 'launchctl unload /Library/LaunchDaemons/re.frida.server.plist'
   ssh root@<device-ip> 'launchctl load /Library/LaunchDaemons/re.frida.server.plist'
   ```

2. **SSH Connection Issues**
   ```bash
   # Install OpenSSH via Cydia
   # Default credentials: root/alpine (CHANGE IMMEDIATELY)
   
   # Change root password
   ssh root@<device-ip> 'passwd'
   ```

3. **Network Connectivity**
   ```bash
   # Ensure device and computer are on same network
   ping <device-ip>
   
   # Check firewall settings on device
   ```

4. **App Crashes**
   ```bash
   # Some apps have anti-debugging protection
   # Check crash logs in /var/mobile/Library/Logs/CrashReporter/
   
   # Use stealth techniques or bypass detection
   ```

## Security Considerations

### Device Security:
- Change default SSH password immediately
- Use SSH keys instead of passwords
- Keep jailbreak tools updated
- Only install trusted repositories

### Testing Safety:
- Use dedicated test devices
- Backup device before jailbreaking
- Test in isolated network environment
- Be aware of warranty implications

### Anti-Jailbreak Detection:
Many apps detect jailbroken devices:
- File system checks
- API availability checks
- Cydia presence detection
- Process name detection

## iOS-Specific Scripts

### SSL Pinning Bypass:
```javascript
// Bypass SSL pinning in NSURLSession
var NSURLSession = ObjC.classes.NSURLSession;
var originalMethod = NSURLSession['- URLSession:didReceiveChallenge:completionHandler:'];

Interceptor.attach(originalMethod.implementation, {
    onEnter: function(args) {
        console.log("[*] SSL challenge intercepted");
        
        // Call completion handler with allow disposition
        var completionHandler = new ObjC.Block(args[4]);
        completionHandler(1, null); // NSURLSessionAuthChallengeUseCredential
    }
});
```

### Touch ID/Face ID Bypass:
```javascript
// Hook LAContext evaluatePolicy
var LAContext = ObjC.classes.LAContext;
var evaluatePolicy = LAContext['- evaluatePolicy:localizedReason:reply:'];

Interceptor.attach(evaluatePolicy.implementation, {
    onEnter: function(args) {
        console.log("[*] Biometric authentication bypassed");
        
        var block = new ObjC.Block(args[4]);
        block(true, null); // Success
    }
});
```

## Next Steps

1. Explore iOS-specific scripts in `/frida-scripts/ios/`
2. Practice with iOS apps in `/Applications/`
3. Learn Objective-C and Swift basics
4. Study iOS security architecture
5. Join iOS security communities for advanced techniques