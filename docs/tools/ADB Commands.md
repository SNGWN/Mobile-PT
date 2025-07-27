# ADB - Android Debug Bridge

## Table of Contents
1. [ADB Architecture](#adb-architecture)
2. [Connection Commands](#connection-commands)
3. [Device Management](#device-management)
4. [Application Management](#application-management)
5. [Data Operations](#data-operations)
6. [System Operations](#system-operations)

## ADB Architecture

**ADB has 3 components:**
1. **Client** - Computer system through which pentester passes commands to Android device
2. **Daemon** - Background process running on Android device that executes commands
3. **Server** - Computer machine that sends commands to Android device

## Connection Commands
```bash
# Connect to device on specific port (default: 5555)
adb connect <IP>:<port>

# Disconnect specific device, or all devices if no IP specified
adb disconnect <IP>

# Reconnect to currently connected device
adb reconnect

# List all connected devices
adb devices
```

## Device Management

```bash
# Get device shell
adb shell

# Show logs for specific application
adb logcat | grep <App Name>

# Reboot device into selected mode
adb reboot <bootloader/recovery/sideload>
```

## Application Management

### Installation
```bash
# Install application on device
adb install <application.apk>

# Installation options:
#   -l : Forward Lock Application
#   -r : Replace Existing Application
#   -t : Allow test package
#   -s : Install Application on SD-card
#   -g : Grant all Runtime permissions
```

### Uninstallation
```bash
# Uninstall application from device
adb uninstall <package name>

# Uninstall options:
#   -k : Don't remove data and cache directories
```

### Sideloading
```bash
# Sideload specified package
adb sideload <package name>
```

## Data Operations

### File Transfer
```bash
# Upload file or folder to specific location on device
adb push <File to upload> <Where to upload>

# Download file from device
adb pull <remote file> <local destination>
```

### Backup and Restore
```bash
# Take backup of device
adb backup <options>

# Backup options:
#   -all     : Include all (System and User) applications in backup
#   -shared  : Create backup of shared storage (SD Card)
#   -obb     : Create backup of application extensions stored in obb folder

# Restore device contents from backup file
adb restore <Backup File>
```

## System Operations
