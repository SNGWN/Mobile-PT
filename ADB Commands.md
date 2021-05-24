# ADB - Android Debug Bridge
	**ADB has 3 components**
		1. Client = Computer System, through which pentester will pass commands to android device.
		2. Daemon = Daemon is a background process which runs on android devices. Which Execute Commands on Device.
		3. Server = Server is the Computer Machine which sends commands to android device.
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# ADB Commands :-
 	- adb connect <IP>:<port>												:: Used to connect with android device on specific port (default port is 5555)

	- adb disconnect <IP>													:: Disconnect a specific machine, if used without IP then disconnect all the devices

	- adb reconnect															:: Reconnect to currently connected device

	- adb devices																:: List out all the connected devices

	- adb push <File to upload> <Where to upload>					:: Upload a specific file or folder to specific location on device.

	- adb shell																	:: get Device shell

	- adb logcat |grep <App Name>											:: Show logs for Specific Application

	- adb install <application.apk>										:: Install Application on device
		:: Options that can be used while installation.
			@ -l 					:: Forward Lock Application
			@ -r 					:: Replace Existing Application
			@ -t 					:: Allow test package
			@ -s 					:: Install Application on SD-card
			@ -g 					:: Grant all Runtime permission

	- adb uninstall <package name>										:: Uninstall Application from devices
		:: -k 					:: don't remove data and cache Directories

	- adb backup <option> 													:: Take Backup of device
		:: Options for Device backup
			@ -all 			:: Include all (System and User) Application in backup
			@ -shared		:: Create Backup of Shared Storage (SD Card)
			@ -obb			:: Create Backup of Application Extension stored in obb folder

	- adb restore <Backup File>											:: Restore device contents from backup File

	- adb reboot <bootloader/recovery/sideload>						:: Reboot device into selected mode

	- adb sideload <package name>											:: Sideload specified package
