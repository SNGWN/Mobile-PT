/*
 * Android Root Detection Bypass
 * Bypasses common root detection mechanisms
 * Based on popular codeshare scripts
 */

console.log("[*] Android Root Detection Bypass loaded");

Java.perform(function() {
    
    // RootBeer library bypass
    try {
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        RootBeer.isRooted.implementation = function() {
            console.log("[*] RootBeer.isRooted() bypassed");
            return false;
        };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() {
            console.log("[*] RootBeer.isRootedWithoutBusyBoxCheck() bypassed");
            return false;
        };
        console.log("[+] RootBeer library hooked");
    } catch (e) {
        console.log("[-] RootBeer library not found");
    }

    // Generic root detection bypass
    var rootDetectionMethods = [
        "isDeviceRooted",
        "isRooted",
        "checkRoot",
        "detectRoot",
        "isJailbroken",
        "hasRoot",
        "rootCheck",
        "checkSU"
    ];

    // Hook common class names that might contain root detection
    var rootDetectionClasses = [
        "com.example.rootdetection",
        "com.security.rootcheck",
        "com.application.security",
        "com.app.antiroot"
    ];

    // File-based root detection bypass
    try {
        var File = Java.use("java.io.File");
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            var suspicious_paths = [
                "/system/app/Superuser.apk",
                "/sbin/su",
                "/system/bin/su",
                "/system/xbin/su",
                "/data/local/xbin/su",
                "/data/local/bin/su",
                "/system/sd/xbin/su",
                "/system/bin/failsafe/su",
                "/data/local/su",
                "/su/bin/su",
                "/system/xbin/busybox",
                "/system/bin/busybox",
                "/data/local/busybox",
                "/data/local/xbin/busybox",
                "/system/app/SuperSU",
                "/system/app/SuperSU.apk",
                "/system/app/Kinguser.apk",
                "/data/data/eu.chainfire.supersu",
                "/data/data/com.noshufou.android.su",
                "/data/data/com.koushikdutta.superuser",
                "/data/data/com.thirdparty.superuser",
                "/data/data/com.yellowes.su",
                "/data/data/com.kingroot.kinguser",
                "/data/data/com.kingo.root",
                "/data/data/com.smedialink.oneclickroot",
                "/data/data/com.zhiqupk.root.global",
                "/data/data/com.alephzain.framaroot"
            ];
            
            for (var i = 0; i < suspicious_paths.length; i++) {
                if (path === suspicious_paths[i]) {
                    console.log("[*] File.exists() bypassed for: " + path);
                    return false;
                }
            }
            return this.exists();
        };
        console.log("[+] File.exists() hooked");
    } catch (e) {
        console.log("[-] File.exists() hook failed: " + e);
    }

    // Runtime.exec bypass
    try {
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload("java.lang.String").implementation = function(command) {
            var suspicious_commands = [
                "su",
                "which su",
                "busybox",
                "id"
            ];
            
            for (var i = 0; i < suspicious_commands.length; i++) {
                if (command.includes(suspicious_commands[i])) {
                    console.log("[*] Runtime.exec() bypassed for: " + command);
                    throw new Error("Command blocked");
                }
            }
            return this.exec(command);
        };
        console.log("[+] Runtime.exec() hooked");
    } catch (e) {
        console.log("[-] Runtime.exec() hook failed: " + e);
    }

    // ProcessBuilder bypass
    try {
        var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
        ProcessBuilder.start.implementation = function() {
            var commands = this.command();
            var command_str = commands.toString();
            
            if (command_str.includes("su") || command_str.includes("busybox")) {
                console.log("[*] ProcessBuilder.start() bypassed for: " + command_str);
                throw new Error("Process blocked");
            }
            return this.start();
        };
        console.log("[+] ProcessBuilder.start() hooked");
    } catch (e) {
        console.log("[-] ProcessBuilder.start() hook failed: " + e);
    }

    // Package manager bypass
    try {
        var PackageManager = Java.use("android.app.ApplicationPackageManager");
        PackageManager.getInstalledPackages.implementation = function(flags) {
            var packages = this.getInstalledPackages(flags);
            var filtered_packages = [];
            
            var suspicious_packages = [
                "com.noshufou.android.su",
                "com.noshufou.android.su.elite",
                "eu.chainfire.supersu",
                "com.koushikdutta.superuser",
                "com.thirdparty.superuser",
                "com.yellowes.su",
                "com.topjohnwu.magisk",
                "com.kingroot.kinguser",
                "com.kingo.root",
                "com.smedialink.oneclickroot",
                "com.zhiqupk.root.global",
                "com.alephzain.framaroot"
            ];
            
            for (var i = 0; i < packages.size(); i++) {
                var package_info = packages.get(i);
                var package_name = package_info.packageName.value;
                
                var is_suspicious = false;
                for (var j = 0; j < suspicious_packages.length; j++) {
                    if (package_name === suspicious_packages[j]) {
                        console.log("[*] Hidden suspicious package: " + package_name);
                        is_suspicious = true;
                        break;
                    }
                }
                
                if (!is_suspicious) {
                    filtered_packages.push(package_info);
                }
            }
            
            var ArrayList = Java.use("java.util.ArrayList");
            var filtered_list = ArrayList.$new();
            for (var k = 0; k < filtered_packages.length; k++) {
                filtered_list.add(filtered_packages[k]);
            }
            
            return filtered_list;
        };
        console.log("[+] PackageManager.getInstalledPackages() hooked");
    } catch (e) {
        console.log("[-] PackageManager.getInstalledPackages() hook failed: " + e);
    }

    // Native library check bypass
    try {
        var System = Java.use("java.lang.System");
        System.loadLibrary.implementation = function(library) {
            console.log("[*] System.loadLibrary() called for: " + library);
            try {
                this.loadLibrary(library);
            } catch (e) {
                console.log("[*] Library load failed, continuing: " + e);
            }
        };
        console.log("[+] System.loadLibrary() hooked");
    } catch (e) {
        console.log("[-] System.loadLibrary() hook failed: " + e);
    }

    // Build.TAGS bypass
    try {
        var Build = Java.use("android.os.Build");
        Build.TAGS.value = "release-keys";
        console.log("[*] Build.TAGS set to: release-keys");
    } catch (e) {
        console.log("[-] Build.TAGS modification failed: " + e);
    }

    // Build properties bypass
    try {
        var SystemProperties = Java.use("android.os.SystemProperties");
        SystemProperties.get.overload("java.lang.String").implementation = function(key) {
            var suspicious_properties = [
                "ro.debuggable",
                "ro.secure",
                "service.adb.root"
            ];
            
            for (var i = 0; i < suspicious_properties.length; i++) {
                if (key === suspicious_properties[i]) {
                    console.log("[*] SystemProperties.get() bypassed for: " + key);
                    if (key === "ro.debuggable") return "0";
                    if (key === "ro.secure") return "1";
                    if (key === "service.adb.root") return "0";
                }
            }
            return this.get(key);
        };
        console.log("[+] SystemProperties.get() hooked");
    } catch (e) {
        console.log("[-] SystemProperties.get() hook failed: " + e);
    }

    console.log("[*] Android Root Detection Bypass setup complete!");
});