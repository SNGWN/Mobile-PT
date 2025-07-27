/**
 * Flutter Platform Channel Monitor
 * Author: Mobile-PT Toolkit
 * Description: Monitors platform channel communication between Dart and native code in Flutter apps
 * Usage: frida -U -l flutter-platform-channel-monitor.js <package_name>
 */

setTimeout(function() {
    console.log("[*] Starting Flutter Platform Channel Monitor...");
    
    if (Java.available) {
        Java.perform(function() {
            console.log("[*] Monitoring Flutter platform channels on Android");
            
            // ==============================================
            // Method Channel Monitoring
            // ==============================================
            
            try {
                var MethodChannel = Java.use("io.flutter.plugin.common.MethodChannel");
                
                // Hook invokeMethod calls (Dart to Native)
                var invokeMethodOverloads = MethodChannel.invokeMethod.overloads;
                
                invokeMethodOverloads.forEach(function(overload) {
                    overload.implementation = function() {
                        var method = arguments[0];
                        var args = arguments.length > 1 ? arguments[1] : null;
                        
                        console.log("\n[*] ===== METHOD CHANNEL CALL =====");
                        console.log("[*] Method: " + method);
                        console.log("[*] Channel: " + this.name.value);
                        
                        if (args) {
                            try {
                                console.log("[*] Arguments: " + JSON.stringify(args));
                            } catch (e) {
                                console.log("[*] Arguments: " + args.toString());
                            }
                        }
                        
                        // Check for sensitive data patterns
                        var methodStr = method.toString().toLowerCase();
                        var argsStr = args ? args.toString().toLowerCase() : "";
                        
                        if (methodStr.includes("password") || methodStr.includes("token") || methodStr.includes("secret") ||
                            argsStr.includes("password") || argsStr.includes("token") || argsStr.includes("secret")) {
                            console.log("[!] SENSITIVE DATA DETECTED in method call!");
                        }
                        
                        if (methodStr.includes("http") || methodStr.includes("network") || methodStr.includes("request")) {
                            console.log("[!] NETWORK-RELATED method call detected!");
                        }
                        
                        if (methodStr.includes("storage") || methodStr.includes("preferences") || methodStr.includes("database")) {
                            console.log("[!] STORAGE-RELATED method call detected!");
                        }
                        
                        console.log("[*] ================================\n");
                        
                        return overload.apply(this, arguments);
                    };
                });
                
                console.log("[✓] Method channel monitoring enabled");
            } catch (e) {
                console.log("[!] Method channel hook failed: " + e);
            }

            // ==============================================
            // Platform Message Monitoring (Lower Level)
            // ==============================================
            
            try {
                var FlutterJNI = Java.use("io.flutter.embedding.engine.FlutterJNI");
                
                // Hook native platform message calls
                FlutterJNI.nativePlatformMessage.implementation = function(channel, message, responseId) {
                    console.log("\n[*] ===== PLATFORM MESSAGE =====");
                    console.log("[*] Channel: " + channel);
                    console.log("[*] Response ID: " + responseId);
                    
                    if (message) {
                        try {
                            // Try to decode message as string
                            var messageStr = Java.use("java.lang.String").$new(message);
                            console.log("[*] Message: " + messageStr);
                            
                            // Check for sensitive patterns
                            var msgLower = messageStr.toLowerCase();
                            if (msgLower.includes("password") || msgLower.includes("token") || msgLower.includes("secret") ||
                                msgLower.includes("api_key") || msgLower.includes("credential")) {
                                console.log("[!] SENSITIVE DATA in platform message!");
                            }
                        } catch (e) {
                            console.log("[*] Message (binary): " + message.length + " bytes");
                        }
                    }
                    
                    console.log("[*] =============================\n");
                    
                    return this.nativePlatformMessage(channel, message, responseId);
                };
                
                console.log("[✓] Platform message monitoring enabled");
            } catch (e) {
                console.log("[!] Platform message hook failed: " + e);
            }

            // ==============================================
            // Event Channel Monitoring
            // ==============================================
            
            try {
                var EventChannel = Java.use("io.flutter.plugin.common.EventChannel");
                
                // Hook setStreamHandler
                EventChannel.setStreamHandler.implementation = function(handler) {
                    console.log("[*] Event channel stream handler set for: " + this.name.value);
                    
                    if (handler) {
                        // Wrap the original handler to monitor events
                        var originalOnListen = handler.onListen;
                        var originalOnCancel = handler.onCancel;
                        
                        if (originalOnListen) {
                            handler.onListen = function(arguments, events) {
                                console.log("[*] Event channel onListen: " + this.toString());
                                return originalOnListen.call(this, arguments, events);
                            };
                        }
                        
                        if (originalOnCancel) {
                            handler.onCancel = function(arguments) {
                                console.log("[*] Event channel onCancel: " + this.toString());
                                return originalOnCancel.call(this, arguments);
                            };
                        }
                    }
                    
                    return this.setStreamHandler(handler);
                };
                
                console.log("[✓] Event channel monitoring enabled");
            } catch (e) {
                console.log("[!] Event channel hook failed: " + e);
            }

            // ==============================================
            // Common Flutter Plugin Monitoring
            // ==============================================
            
            try {
                // Monitor shared_preferences plugin
                Java.enumerateLoadedClasses({
                    onMatch: function(className) {
                        if (className.includes("shared_preferences") || className.includes("SharedPreferences")) {
                            console.log("[*] Found shared_preferences plugin: " + className);
                            
                            try {
                                var SharedPrefClass = Java.use(className);
                                console.log("[*] Monitoring shared_preferences: " + className);
                                // Additional monitoring can be added here
                            } catch (e) {
                                // Skip if can't hook
                            }
                        }
                        
                        if (className.includes("http") || className.includes("Http")) {
                            console.log("[*] Found HTTP-related class: " + className);
                        }
                        
                        if (className.includes("secure_storage") || className.includes("SecureStorage")) {
                            console.log("[*] Found secure storage class: " + className);
                        }
                        
                        if (className.includes("location") || className.includes("Location")) {
                            console.log("[*] Found location-related class: " + className);
                        }
                        
                        if (className.includes("camera") || className.includes("Camera")) {
                            console.log("[*] Found camera-related class: " + className);
                        }
                    },
                    onComplete: function() {}
                });
                
                console.log("[✓] Plugin enumeration completed");
            } catch (e) {
                console.log("[!] Plugin monitoring failed: " + e);
            }

            // ==============================================
            // Binary Messenger Monitoring (Flutter 2.0+)
            // ==============================================
            
            try {
                var BinaryMessenger = Java.use("io.flutter.plugin.common.BinaryMessenger");
                
                // Hook send method
                var sendMethod = BinaryMessenger.send.overload("java.lang.String", "java.nio.ByteBuffer", "io.flutter.plugin.common.BinaryMessenger$BinaryReply");
                sendMethod.implementation = function(channel, message, callback) {
                    console.log("\n[*] ===== BINARY MESSENGER =====");
                    console.log("[*] Channel: " + channel);
                    
                    if (message) {
                        console.log("[*] Message size: " + message.remaining() + " bytes");
                        
                        // Try to read message content
                        try {
                            var messageBytes = Java.array("byte", message.remaining());
                            message.get(messageBytes);
                            message.rewind(); // Reset position for actual call
                            
                            var messageStr = Java.use("java.lang.String").$new(messageBytes);
                            console.log("[*] Message content: " + messageStr);
                        } catch (e) {
                            console.log("[*] Binary message content (couldn't decode as string)");
                        }
                    }
                    
                    console.log("[*] =============================\n");
                    
                    return this.send(channel, message, callback);
                };
                
                console.log("[✓] Binary messenger monitoring enabled");
            } catch (e) {
                console.log("[!] Binary messenger hook failed: " + e);
            }

            // ==============================================
            // Flutter Engine Monitoring
            // ==============================================
            
            try {
                var FlutterEngine = Java.use("io.flutter.embedding.engine.FlutterEngine");
                
                // Monitor plugin registration
                FlutterEngine.getPlugins.implementation = function() {
                    var plugins = this.getPlugins();
                    console.log("[*] Flutter engine has " + plugins.size() + " plugins registered");
                    
                    // List all plugins
                    var iterator = plugins.iterator();
                    while (iterator.hasNext()) {
                        var plugin = iterator.next();
                        console.log("[*] Plugin: " + plugin.getClass().getName());
                    }
                    
                    return plugins;
                };
                
                console.log("[✓] Flutter engine monitoring enabled");
            } catch (e) {
                console.log("[!] Flutter engine hook failed: " + e);
            }

            console.log("[*] Flutter Platform Channel Monitor setup completed!");
        });
    }
    
    // ==============================================
    // iOS Platform Channel Monitoring
    // ==============================================
    
    if (ObjC.available) {
        console.log("[*] Monitoring Flutter platform channels on iOS");
        
        try {
            // Hook FlutterMethodChannel
            var FlutterMethodChannel = ObjC.classes.FlutterMethodChannel;
            if (FlutterMethodChannel) {
                var invokeMethod = FlutterMethodChannel['- invokeMethod:arguments:'];
                if (invokeMethod) {
                    Interceptor.attach(invokeMethod.implementation, {
                        onEnter: function(args) {
                            var method = new ObjC.Object(args[2]);
                            var arguments = new ObjC.Object(args[3]);
                            
                            console.log("\n[*] ===== iOS METHOD CHANNEL =====");
                            console.log("[*] Method: " + method.toString());
                            console.log("[*] Arguments: " + arguments.toString());
                            console.log("[*] ===============================\n");
                        }
                    });
                }
            }
            
            console.log("[✓] iOS method channel monitoring enabled");
        } catch (e) {
            console.log("[!] iOS platform channel monitoring failed: " + e);
        }
    }
    
}, 1000);