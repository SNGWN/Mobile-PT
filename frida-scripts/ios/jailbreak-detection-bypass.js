/*
 * iOS Jailbreak Detection Bypass
 * Bypasses common jailbreak detection mechanisms on iOS
 */

console.log("[*] iOS Jailbreak Detection Bypass loaded");

if (ObjC.available) {
    // File existence checks bypass
    var NSFileManager = ObjC.classes.NSFileManager;
    if (NSFileManager) {
        var fileExistsAtPath = NSFileManager['- fileExistsAtPath:'];
        if (fileExistsAtPath) {
            Interceptor.attach(fileExistsAtPath.implementation, {
                onEnter: function(args) {
                    var path = new ObjC.Object(args[2]).toString();
                    var suspicious_paths = [
                        "/Applications/Cydia.app",
                        "/Library/MobileSubstrate/MobileSubstrate.dylib",
                        "/bin/bash",
                        "/usr/sbin/sshd",
                        "/etc/apt",
                        "/private/var/lib/apt/",
                        "/private/var/lib/cydia",
                        "/private/var/mobile/Library/SBSettings/Themes",
                        "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
                        "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
                        "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
                        "/private/var/lib/dpkg/info/most.list",
                        "/Applications/FakeCarrier.app",
                        "/Applications/Icy.app",
                        "/Applications/IntelliScreen.app",
                        "/Applications/MxTube.app",
                        "/Applications/RockApp.app",
                        "/Applications/SBSettings.app",
                        "/Applications/WinterBoard.app",
                        "/Applications/blackra1n.app",
                        "/Library/MobileSubstrate/MobileSubstrate.dylib",
                        "/var/cache/apt",
                        "/var/lib/apt",
                        "/var/lib/cydia",
                        "/var/log/syslog",
                        "/var/tmp/cydia.log",
                        "/bin/sh",
                        "/usr/bin/ssh",
                        "/usr/libexec/ssh-keysign",
                        "/usr/sbin/sshd",
                        "/etc/ssh/sshd_config",
                        "/private/var/tmp/cydia.log",
                        "/usr/libexec/sftp-server",
                        "/usr/bin/scp"
                    ];
                    
                    for (var i = 0; i < suspicious_paths.length; i++) {
                        if (path.includes(suspicious_paths[i])) {
                            console.log("[*] fileExistsAtPath bypassed for: " + path);
                            this.bypass = true;
                            return;
                        }
                    }
                },
                onLeave: function(retval) {
                    if (this.bypass) {
                        retval.replace(0); // Return NO (false)
                        this.bypass = false;
                    }
                }
            });
            console.log("[+] NSFileManager fileExistsAtPath hooked");
        }
    }

    // fopen bypass for C-level file access
    var fopen = Module.findExportByName("libsystem_c.dylib", "fopen");
    if (fopen) {
        Interceptor.attach(fopen, {
            onEnter: function(args) {
                var path = Memory.readUtf8String(args[0]);
                var suspicious_paths = [
                    "/Applications/Cydia.app",
                    "/Library/MobileSubstrate/",
                    "/bin/bash",
                    "/usr/sbin/sshd",
                    "/etc/apt"
                ];
                
                for (var i = 0; i < suspicious_paths.length; i++) {
                    if (path && path.includes(suspicious_paths[i])) {
                        console.log("[*] fopen bypassed for: " + path);
                        args[0] = Memory.allocUtf8String("/dev/null");
                        break;
                    }
                }
            }
        });
        console.log("[+] fopen hooked");
    }

    // stat/lstat bypass
    var stat = Module.findExportByName("libsystem_kernel.dylib", "stat");
    if (stat) {
        Interceptor.attach(stat, {
            onEnter: function(args) {
                var path = Memory.readUtf8String(args[0]);
                if (path && (path.includes("/Applications/Cydia.app") || 
                           path.includes("/Library/MobileSubstrate/") ||
                           path.includes("/bin/bash") ||
                           path.includes("/usr/sbin/sshd"))) {
                    console.log("[*] stat bypassed for: " + path);
                    this.bypass = true;
                }
            },
            onLeave: function(retval) {
                if (this.bypass) {
                    retval.replace(-1); // Return error
                    this.bypass = false;
                }
            }
        });
        console.log("[+] stat hooked");
    }

    // access() bypass
    var access = Module.findExportByName("libsystem_kernel.dylib", "access");
    if (access) {
        Interceptor.attach(access, {
            onEnter: function(args) {
                var path = Memory.readUtf8String(args[0]);
                if (path && (path.includes("/Applications/Cydia.app") || 
                           path.includes("/Library/MobileSubstrate/") ||
                           path.includes("/bin/bash") ||
                           path.includes("/usr/sbin/sshd"))) {
                    console.log("[*] access bypassed for: " + path);
                    this.bypass = true;
                }
            },
            onLeave: function(retval) {
                if (this.bypass) {
                    retval.replace(-1); // Return error
                    this.bypass = false;
                }
            }
        });
        console.log("[+] access hooked");
    }

    // dyld bypass for library detection
    var dlopen = Module.findExportByName("libdyld.dylib", "dlopen");
    if (dlopen) {
        Interceptor.attach(dlopen, {
            onEnter: function(args) {
                var path = Memory.readUtf8String(args[0]);
                if (path && path.includes("MobileSubstrate")) {
                    console.log("[*] dlopen bypassed for: " + path);
                    args[0] = Memory.allocUtf8String("/dev/null");
                }
            }
        });
        console.log("[+] dlopen hooked");
    }

    // Bypass URL scheme checks (cydia://)
    var UIApplication = ObjC.classes.UIApplication;
    if (UIApplication) {
        var canOpenURL = UIApplication['- canOpenURL:'];
        if (canOpenURL) {
            Interceptor.attach(canOpenURL.implementation, {
                onEnter: function(args) {
                    var url = new ObjC.Object(args[2]);
                    var urlString = url.absoluteString().toString();
                    if (urlString.includes("cydia://")) {
                        console.log("[*] canOpenURL bypassed for: " + urlString);
                        this.bypass = true;
                    }
                },
                onLeave: function(retval) {
                    if (this.bypass) {
                        retval.replace(0); // Return NO
                        this.bypass = false;
                    }
                }
            });
            console.log("[+] UIApplication canOpenURL hooked");
        }
    }

    // Bypass sandbox violation detection
    var sandbox_check = Module.findExportByName("libsystem_sandbox.dylib", "sandbox_check");
    if (sandbox_check) {
        Interceptor.attach(sandbox_check, {
            onLeave: function(retval) {
                console.log("[*] sandbox_check bypassed");
                retval.replace(0); // Return allowed
            }
        });
        console.log("[+] sandbox_check hooked");
    }

    // Bypass getpid/getppid checks (anti-debugging)
    var getpid = Module.findExportByName("libsystem_kernel.dylib", "getpid");
    if (getpid) {
        Interceptor.attach(getpid, {
            onLeave: function(retval) {
                // Return a consistent PID to avoid detection
                retval.replace(1234);
            }
        });
    }

    // Bypass sysctl checks
    var sysctl = Module.findExportByName("libsystem_kernel.dylib", "sysctl");
    if (sysctl) {
        Interceptor.attach(sysctl, {
            onEnter: function(args) {
                var name = Memory.readPointer(args[0]);
                var namelen = args[1].toInt32();
                
                // Check if it's kern.proc.pid request (debugging detection)
                if (namelen == 4) {
                    var mib = [];
                    for (var i = 0; i < 4; i++) {
                        mib.push(Memory.readInt(name.add(i * 4)));
                    }
                    
                    if (mib[0] == 1 && mib[1] == 14 && mib[2] == 1) { // CTL_KERN, KERN_PROC, KERN_PROC_PID
                        console.log("[*] sysctl debugging detection bypassed");
                        this.bypass = true;
                    }
                }
            },
            onLeave: function(retval) {
                if (this.bypass) {
                    retval.replace(-1); // Return error
                    this.bypass = false;
                }
            }
        });
        console.log("[+] sysctl hooked");
    }

    // Bypass ptrace anti-debugging
    var ptrace = Module.findExportByName("libsystem_kernel.dylib", "ptrace");
    if (ptrace) {
        Interceptor.attach(ptrace, {
            onEnter: function(args) {
                var request = args[0].toInt32();
                if (request == 31) { // PT_DENY_ATTACH
                    console.log("[*] ptrace(PT_DENY_ATTACH) bypassed");
                    args[0] = ptr(0);
                }
            }
        });
        console.log("[+] ptrace hooked");
    }

    // Bypass exit() calls (anti-debugging)
    var exit = Module.findExportByName("libsystem_c.dylib", "exit");
    if (exit) {
        Interceptor.attach(exit, {
            onEnter: function(args) {
                console.log("[*] exit() call intercepted and blocked");
                args[0] = ptr(0); // Change exit code to 0
            }
        });
        console.log("[+] exit hooked");
    }

    console.log("[*] iOS Jailbreak Detection Bypass setup complete!");
} else {
    console.log("[-] Objective-C runtime not available");
}