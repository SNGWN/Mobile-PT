/*
 * Android Crypto Hook - Monitor Cryptographic Operations
 * Purpose: Monitor and log cryptographic operations in Android apps
 * Useful for: Finding weak crypto implementations, key analysis, algorithm detection
 */

console.log("[*] Android Crypto Hook loaded");

Java.perform(function() {
    
    // Monitor Cipher operations
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        
        // Hook Cipher.getInstance()
        Cipher.getInstance.overload("java.lang.String").implementation = function(transformation) {
            console.log("[*] Cipher.getInstance() called with transformation: " + transformation);
            
            // Check for weak algorithms
            var weakAlgos = ["DES", "3DES", "RC4", "MD5"];
            weakAlgos.forEach(function(algo) {
                if (transformation.toUpperCase().includes(algo)) {
                    console.log("[!] WEAK ALGORITHM DETECTED: " + transformation);
                }
            });
            
            return this.getInstance(transformation);
        };

        // Hook init() methods
        Cipher.init.overload("int", "java.security.Key").implementation = function(opmode, key) {
            var mode = "";
            switch(opmode) {
                case 1: mode = "ENCRYPT_MODE"; break;
                case 2: mode = "DECRYPT_MODE"; break;
                case 3: mode = "WRAP_MODE"; break;
                case 4: mode = "UNWRAP_MODE"; break;
            }
            
            console.log("[*] Cipher.init() called with mode: " + mode);
            console.log("    Key algorithm: " + key.getAlgorithm());
            console.log("    Key format: " + key.getFormat());
            
            return this.init(opmode, key);
        };

        // Hook doFinal() for data inspection
        Cipher.doFinal.overload("[B").implementation = function(input) {
            console.log("[*] Cipher.doFinal() called");
            console.log("    Input length: " + input.length + " bytes");
            
            // Log first few bytes (be careful with sensitive data)
            if (input.length > 0) {
                var preview = "";
                for (var i = 0; i < Math.min(input.length, 16); i++) {
                    preview += ("0" + (input[i] & 0xFF).toString(16)).slice(-2) + " ";
                }
                console.log("    Input preview: " + preview);
            }
            
            var result = this.doFinal(input);
            console.log("    Output length: " + result.length + " bytes");
            
            return result;
        };
        
        console.log("[+] Cipher hooks installed");
    } catch (e) {
        console.log("[-] Cipher hook failed: " + e);
    }

    // Monitor MessageDigest (Hash) operations
    try {
        var MessageDigest = Java.use("java.security.MessageDigest");
        
        MessageDigest.getInstance.overload("java.lang.String").implementation = function(algorithm) {
            console.log("[*] MessageDigest.getInstance() called with: " + algorithm);
            
            // Check for weak hash algorithms
            var weakHashes = ["MD5", "SHA1"];
            if (weakHashes.includes(algorithm.toUpperCase())) {
                console.log("[!] WEAK HASH ALGORITHM DETECTED: " + algorithm);
            }
            
            return this.getInstance(algorithm);
        };

        MessageDigest.digest.overload("[B").implementation = function(input) {
            console.log("[*] MessageDigest.digest() called");
            console.log("    Input length: " + input.length + " bytes");
            
            var result = this.digest(input);
            console.log("    Hash length: " + result.length + " bytes");
            
            return result;
        };
        
        console.log("[+] MessageDigest hooks installed");
    } catch (e) {
        console.log("[-] MessageDigest hook failed: " + e);
    }

    // Monitor KeyGenerator operations
    try {
        var KeyGenerator = Java.use("javax.crypto.KeyGenerator");
        
        KeyGenerator.getInstance.overload("java.lang.String").implementation = function(algorithm) {
            console.log("[*] KeyGenerator.getInstance() called with: " + algorithm);
            return this.getInstance(algorithm);
        };

        KeyGenerator.generateKey.implementation = function() {
            console.log("[*] KeyGenerator.generateKey() called");
            var key = this.generateKey();
            console.log("    Generated key algorithm: " + key.getAlgorithm());
            console.log("    Generated key format: " + key.getFormat());
            return key;
        };
        
        console.log("[+] KeyGenerator hooks installed");
    } catch (e) {
        console.log("[-] KeyGenerator hook failed: " + e);
    }

    // Monitor SecureRandom operations
    try {
        var SecureRandom = Java.use("java.security.SecureRandom");
        
        SecureRandom.getInstance.overload("java.lang.String").implementation = function(algorithm) {
            console.log("[*] SecureRandom.getInstance() called with: " + algorithm);
            
            // Check for weak PRNG
            if (algorithm === "SHA1PRNG") {
                console.log("[!] WEAK PRNG DETECTED: SHA1PRNG");
            }
            
            return this.getInstance(algorithm);
        };

        SecureRandom.nextBytes.implementation = function(bytes) {
            console.log("[*] SecureRandom.nextBytes() called for " + bytes.length + " bytes");
            return this.nextBytes(bytes);
        };
        
        console.log("[+] SecureRandom hooks installed");
    } catch (e) {
        console.log("[-] SecureRandom hook failed: " + e);
    }

    // Monitor Base64 encoding/decoding
    try {
        var Base64 = Java.use("android.util.Base64");
        
        Base64.encode.overload("[B", "int").implementation = function(input, flags) {
            console.log("[*] Base64.encode() called");
            console.log("    Input length: " + input.length + " bytes");
            
            var result = this.encode(input, flags);
            console.log("    Encoded length: " + result.length + " bytes");
            
            return result;
        };

        Base64.decode.overload("java.lang.String", "int").implementation = function(str, flags) {
            console.log("[*] Base64.decode() called");
            console.log("    Input: " + str.substring(0, Math.min(str.length, 50)) + "...");
            
            var result = this.decode(str, flags);
            console.log("    Decoded length: " + result.length + " bytes");
            
            return result;
        };
        
        console.log("[+] Base64 hooks installed");
    } catch (e) {
        console.log("[-] Base64 hook failed: " + e);
    }

    // Monitor URL encoding/decoding
    try {
        var URLEncoder = Java.use("java.net.URLEncoder");
        var URLDecoder = Java.use("java.net.URLDecoder");
        
        URLEncoder.encode.overload("java.lang.String", "java.lang.String").implementation = function(s, enc) {
            console.log("[*] URLEncoder.encode() called");
            console.log("    Input: " + s.substring(0, Math.min(s.length, 100)));
            
            var result = this.encode(s, enc);
            return result;
        };

        URLDecoder.decode.overload("java.lang.String", "java.lang.String").implementation = function(s, enc) {
            console.log("[*] URLDecoder.decode() called");
            console.log("    Input: " + s.substring(0, Math.min(s.length, 100)));
            
            var result = this.decode(s, enc);
            return result;
        };
        
        console.log("[+] URL encoding hooks installed");
    } catch (e) {
        console.log("[-] URL encoding hook failed: " + e);
    }

    // Monitor key storage in KeyStore
    try {
        var KeyStore = Java.use("java.security.KeyStore");
        
        KeyStore.getKey.implementation = function(alias, password) {
            console.log("[*] KeyStore.getKey() called for alias: " + alias);
            
            var key = this.getKey(alias, password);
            if (key) {
                console.log("    Retrieved key algorithm: " + key.getAlgorithm());
            }
            
            return key;
        };

        KeyStore.setKeyEntry.overload("java.lang.String", "java.security.Key", "[C", "[Ljava.security.cert.Certificate;").implementation = function(alias, key, password, chain) {
            console.log("[*] KeyStore.setKeyEntry() called");
            console.log("    Alias: " + alias);
            console.log("    Key algorithm: " + key.getAlgorithm());
            
            return this.setKeyEntry(alias, key, password, chain);
        };
        
        console.log("[+] KeyStore hooks installed");
    } catch (e) {
        console.log("[-] KeyStore hook failed: " + e);
    }

    console.log("[*] Android Crypto Hook setup complete!");
});