Java.perform(function() {
    console.log("[+] Starting Comprehensive Emulator Bypass...");
    
    // 1. Build CLASS BYPASS
    try {
        var Build = Java.use("android.os.Build");
        
        // Direct field modification
        Build.MODEL.value = "SM-G973F";
        Build.MANUFACTURER.value = "samsung";
        Build.BRAND.value = "samsung";
        Build.DEVICE.value = "starqlteue";
        Build.PRODUCT.value = "starqlteue";
        Build.HARDWARE.value = "samsungexynos9810";
        Build.FINGERPRINT.value = "samsung/starqlteue/starqlte:10/QP1A.190711.020/G973FXXU6ETG7:user/release-keys";
        
        console.log("[+] Build class bypassed");
    } catch(e) {
        console.log("[-] Build bypass failed: " + e);
    }
    
    // 2. TELEPHONY MANAGER BYPASS
    try {
        var TelephonyManager = Java.use("android.telephony.TelephonyManager");
        
        TelephonyManager.getDeviceId.implementation = function() {
            return "357175080448741";
        };
        
        TelephonyManager.getImei.implementation = function() {
            return "357175080448741";
        };
        
        TelephonyManager.getSimOperatorName.implementation = function() {
            return "Airtel";
        };
        
        TelephonyManager.getNetworkOperatorName.implementation = function() {
            return "Airtel";
        };
        
        TelephonyManager.getPhoneType.implementation = function() {
            return 1; // PHONE_TYPE_GSM
        };
        
        console.log("[+] TelephonyManager bypassed");
    } catch(e) {
        console.log("[-] Telephony bypass failed: " + e);
    }
    
    // 3. SETTINGS SECURE BYPASS
    try {
        var SettingsSecure = Java.use("android.provider.Settings$Secure");
        
        SettingsSecure.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, key) {
            if (key === "android_id") {
                return "8f16e67e7a8b4d8a";
            }
            return this.getString.call(this, cr, key);
        };
        
        console.log("[+] SettingsSecure bypassed");
    } catch(e) {
        console.log("[-] SettingsSecure bypass failed: " + e);
    }
    
    // 4. SYSTEM PROPERTIES BYPASS
    try {
        var SystemProperties = Java.use("android.os.SystemProperties");
        
        SystemProperties.get.overload('java.lang.String').implementation = function(key) {
            var blockedProps = ["ro.kernel.qemu", "ro.boot.qemu", "ro.hardware", "ro.product.model", "ro.build.product"];
            if (blockedProps.includes(key)) {
                return "0";
            }
            return this.get.call(this, key);
        };
        
        SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function(key, def) {
            if (key === "ro.kernel.qemu") {
                return "0";
            }
            if (key === "ro.hardware") {
                return "goldfish";
            }
            return this.get.call(this, key, def);
        };
        
        console.log("[+] SystemProperties bypassed");
    } catch(e) {
        console.log("[-] SystemProperties bypass failed: " + e);
    }
    
    // 5. DEBUG CHECK BYPASS
    try {
        var Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function() {
            return false;
        };
        
        var ActivityManager = Java.use("android.app.ActivityManager");
        ActivityManager.isUserAMonkey.implementation = function() {
            return false;
        };
        
        console.log("[+] Debug checks bypassed");
    } catch(e) {
        console.log("[-] Debug bypass failed: " + e);
    }
    
    // 6. PACKAGE MANAGER BYPASS
    try {
        var PackageManager = Java.use("android.content.pm.PackageManager");
        
        PackageManager.getInstalledPackages.implementation = function(flags) {
            var list = this.getInstalledPackages.call(this, flags);
            // FRIDA related packages hatao
            for (var i = 0; i < list.size(); i++) {
                var packageInfo = list.get(i);
                var packageName = packageInfo.packageName.value;
                if (packageName.includes("frida") || packageName.includes("xposed")) {
                    list.remove(i);
                    i--;
                }
            }
            return list;
        };
        
        console.log("[+] PackageManager bypassed");
    } catch(e) {
        console.log("[-] PackageManager bypass failed: " + e);
    }
});