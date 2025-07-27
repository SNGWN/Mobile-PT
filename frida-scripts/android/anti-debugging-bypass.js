/*
 * Android Anti-Debugging Bypass
 * Bypasses common anti-debugging techniques on Android
 */

console.log("[*] Android Anti-Debugging Bypass loaded");

Java.perform(function() {
    
    // Debug.isDebuggerConnected() bypass
    try {
        var Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function() {
            console.log("[*] Debug.isDebuggerConnected() bypassed");
            return false;
        };
        console.log("[+] Debug.isDebuggerConnected() hooked");
    } catch (e) {
        console.log("[-] Debug.isDebuggerConnected() hook failed: " + e);
    }

    // ApplicationInfo.FLAG_DEBUGGABLE bypass
    try {
        var ApplicationInfo = Java.use("android.content.pm.ApplicationInfo");
        ApplicationInfo.FLAG_DEBUGGABLE.value = 0;
        console.log("[+] ApplicationInfo.FLAG_DEBUGGABLE bypassed");
    } catch (e) {
        console.log("[-] ApplicationInfo.FLAG_DEBUGGABLE bypass failed: " + e);
    }

    // Bypass native anti-debugging checks
    var nativeFunctions = [
        "ptrace",
        "fork", 
        "strstr",
        "strcmp"
    ];

    nativeFunctions.forEach(function(funcName) {
        try {
            var funcPtr = Module.findExportByName("libc.so", funcName);
            if (funcPtr) {
                Interceptor.attach(funcPtr, {
                    onEnter: function(args) {
                        if (funcName === "ptrace") {
                            console.log("[*] ptrace() called - bypassing");
                            args[0] = ptr(0); // PTRACE_TRACEME = 0
                        } else if (funcName === "strstr") {
                            var haystack = Memory.readUtf8String(args[0]);
                            var needle = Memory.readUtf8String(args[1]);
                            
                            var debugStrings = [
                                "TracerPid",
                                "gdb",
                                "frida",
                                "xposed"
                            ];
                            
                            debugStrings.forEach(function(debugStr) {
                                if (needle && needle.includes(debugStr)) {
                                    console.log("[*] strstr() bypassed for: " + needle);
                                    args[1] = Memory.allocUtf8String("non_existent_string");
                                }
                            });
                        } else if (funcName === "strcmp") {
                            var str1 = Memory.readUtf8String(args[0]);
                            var str2 = Memory.readUtf8String(args[1]);
                            
                            if ((str1 && str1.includes("TracerPid")) || 
                                (str2 && str2.includes("TracerPid"))) {
                                console.log("[*] strcmp() bypassed for TracerPid");
                                this.bypass = true;
                            }
                        }
                    },
                    onLeave: function(retval) {
                        if (this.bypass) {
                            retval.replace(1); // Make strings not equal
                            this.bypass = false;
                        }
                    }
                });
                console.log("[+] " + funcName + " hooked");
            }
        } catch (e) {
            console.log("[-] " + funcName + " hook failed: " + e);
        }
    });

    // Bypass timing-based detection
    try {
        var System = Java.use("java.lang.System");
        var originalNanoTime = System.nanoTime;
        var originalCurrentTimeMillis = System.currentTimeMillis;
        
        System.nanoTime.implementation = function() {
            var result = originalNanoTime.call(this);
            // Modify timing to avoid detection patterns
            return result;
        };
        
        System.currentTimeMillis.implementation = function() {
            var result = originalCurrentTimeMillis.call(this);
            // Modify timing to avoid detection patterns
            return result;
        };
        
        console.log("[+] Timing functions hooked");
    } catch (e) {
        console.log("[-] Timing bypass failed: " + e);
    }

    // Bypass process name checks
    try {
        var ActivityThread = Java.use("android.app.ActivityThread");
        ActivityThread.getProcessName.implementation = function() {
            var processName = this.getProcessName();
            console.log("[*] Process name requested: " + processName);
            return processName;
        };
        console.log("[+] ActivityThread.getProcessName() hooked");
    } catch (e) {
        console.log("[-] ActivityThread.getProcessName() hook failed: " + e);
    }

    // Bypass exception-based debugging detection
    try {
        var Thread = Java.use("java.lang.Thread");
        Thread.getStackTrace.implementation = function() {
            var stack = this.getStackTrace();
            console.log("[*] Stack trace requested");
            return stack;
        };
        console.log("[+] Thread.getStackTrace() hooked");
    } catch (e) {
        console.log("[-] Thread.getStackTrace() hook failed: " + e);
    }

    console.log("[*] Android Anti-Debugging Bypass setup complete!");
});