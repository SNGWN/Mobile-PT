1. Add your cert normally, it will be stored in your personal store and android will ask you a pin/password... Proceed

2. With a file manager with root capabilities, browse files in **/data/misc/keychain/cacerts-added**. You should see a file here, it's the certificate you have added at step 1.

3. Move this file to **system/etc/security/cacerts** (you will need to mount the system partition r/w.

# commands to Mount Read Only File System into Writeable File System
	1. Mount system RW: mount -o rw,remount /system
	2. Mount system RO: mount -o ro,remount /system

# Copy user CA-Certificate into System CA-Certificates (https://android.stackexchange.com/questions/110927/how-to-mount-system-rewritable-or-read-only-rw-ro)
	--> cp /data/misc/keychain/cacerts-added /system/etc/security/cacerts/

# The misconfigured Firebase instance can be identified by making the following network call:
	https://\<firebaseProjectName\>.firebaseio.com/.json

# JWT Token Format
	--> Header.Paylod.Signature
	--> Header => Algorithm used in Signature
	--> Paylod => Claims (User Data)
	--> Signature => HMAC_SHA256(Base64.encode(header)+"."+Base64.encode(payload),secret)
