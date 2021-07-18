# Create Certificate
    1 - Export Burp certificate to .DER e.g cacert.der
    2 - openssl x509 -inform DER -in cacert.der -out cacert.pem             // Convert .DER (Distinguished Encoding Rule) encoded file into .PEM (Privacy Enhanced Mail) encoded file.
    3 - openssl x509 -subject_hash_old -in cacert.pem |head -1              // Calculate MD5 hash for cacert.pem file and **head -1** will only print 1st list
    4 - mv cacert.pem {hash}.0                                              // rename file with hash output of last command

# Setup Certificate
    1 - adb root                                                            // Get Root access with ADB. Don't need to execute this command if ADB is configured to Root by-default 
    2 - adb remount                                                         // Remount partitions to Read-Write. if a reboot is required, -R will will automatically reboot the device.
    3 - adb push {cert}.0 /system/etc/security/cacerts/                     // Upload Certificate file to Android Certificate Store Directory.
    4 - adb shell chmod 644 /system/etc/security/cacerts/{cert}.0           // Grant Read-Write Permission to Root Owner and Read Permission to other users and groups. 
    5 - adb reboot                                                          // Reboot Android Device to update Certificate Store. 