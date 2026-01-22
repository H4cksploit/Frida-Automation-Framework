Java.perform(function() {
    console.log("🚀 STARTING ULTIMATE EMULATOR + ROOT BYPASS...");
    
    // ==================== ANDROID BUILD SPOOFING ====================
    var Build = Java.use("android.os.Build");
    var Build_VERSION = Java.use("android.os.Build$VERSION");
    
    // Complete Build spoofing
    Build.MANUFACTURER.value = "samsung";
    Build.BRAND.value = "samsung"; 
    Build.MODEL.value = "SM-G998B";
    Build.DEVICE.value = "p3s";
    Build.PRODUCT.value = "p3sxxx";
    Build.HARDWARE.value = "qcom";
    Build.BOARD.value = "taro";
    Build.BOOTLOADER.value = "G998BXXU5EWH5";
    Build.FINGERPRINT.value = "samsung/p3sxxx/p3s:13/TP1A.220624.014/G998BXXU5EWH5:user/release-keys";
    Build.SERIAL.value = "R58M70ZM9SP";
    Build.ID.value = "TP1A.220624.014";
    Build.TAGS.value = "release-keys";
    Build.TYPE.value = "user";
    
    // Version spoofing
    Build_VERSION.SDK_INT.value = 33;
    Build_VERSION.RELEASE.value = "13";
    Build_VERSION.SECURITY_PATCH.value = "2023-08-01";
    
    console.log("✅ Build spoofing completed");
    
    // ==================== ROOT DETECTION BYPASS ====================
    
    // 1. SU BINARY CHECK BYPASS
    var File = Java.use("java.io.File");
    
    File.exists.implementation = function() {
        var path = this.getPath().toLowerCase();
        
        var rootFiles = [
            "/su", "/su/bin", "/su/xbin", "/sbin/su", "/system/bin/su",
            "/system/xbin/su", "/system/bin/.ext/.su", "/system/bin/failsafe/su",
            "/system/sd/xbin/su", "/system/usr/we-need-root/su", "/system/xbin/mu",
            "/system/xbin/sugote", "/system/xbin/sugote-mksh", "/system/xbin/supolicy",
            "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
            "/data/local/tmp/su", "/data/local/tmp/busybox", "/system/bin/busybox",
            "/system/xbin/busybox", "/sbin/busybox", "/data/local/busybox",
            "/system/bin/frida", "/system/xbin/frida", "/data/local/tmp/frida",
            "/system/app/superuser", "/system/app/supersu", "/system/app/magisk",
            "/data/app/com.topjohnwu.magisk", "/data/app/com.noshufou.android.su",
            "/system/bin/magisk", "/system/xbin/magisk", "/data/magisk",
            "/system/bin/.magisk", "/system/xbin/.magisk", "/init.magisk.rc",
            "/overlay.magisk.rc"
        ];
        
        for (var i = 0; i < rootFiles.length; i++) {
            if (path.includes(rootFiles[i])) {
                console.log("🚫 Blocked root file: " + path);
                return false;
            }
        }
        return this.exists.call(this);
    };
    
    // 2. COMMAND EXECUTION BYPASS
    var Runtime = Java.use("java.lang.Runtime");
    
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmd) {
        var command = cmd.join(" ");
        if (command.includes("su") || command.includes("busybox") || 
            command.includes("which su") || command.includes("magisk") ||
            command.includes("frida") || command.includes("xposed")) {
            console.log("🚫 Blocked root command: " + command);
            throw Java.use("java.io.IOException").$new("Command not found");
        }
        return this.exec.call(this, cmd);
    };
    
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if (cmd.includes("su") || cmd.includes("busybox") || 
            cmd.includes("which su") || cmd.includes("magisk")) {
            console.log("🚫 Blocked root command: " + cmd);
            throw Java.use("java.io.IOException").$new("Command not found");
        }
        return this.exec.call(this, cmd);
    };
    
    // 3. PROCESS CHECK BYPASS
    var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
    
    ProcessBuilder.start.implementation = function() {
        var command = this.command.toString().toLowerCase();
        if (command.includes("su") || command.includes("busybox") || command.includes("magisk")) {
            console.log("🚫 Blocked ProcessBuilder: " + command);
            throw Java.use("java.io.IOException").$new("Cannot run program");
        }
        return this.start.call(this);
    };
    
    // 4. PACKAGE MANAGER ROOT APPS BYPASS
    var PackageManager = Java.use("android.content.pm.PackageManager");
    
    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pkgName, flags) {
        var rootApps = [
            "com.noshufou.android.su", "com.thirdparty.superuser", "eu.chainfire.supersu",
            "com.koushikdutta.superuser", "com.zachspong.temprootremovejb", "com.ramdroid.appquarantine",
            "com.topjohnwu.magisk", "com.koushikdutta.rommanager", "com.koushikdutta.rommanager.license",
            "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch", "com.ramdroid.appquarantinepro",
            "com.devadvance.rootcloak", "com.devadvance.rootcloakplus", "com.zachspong.temprootremovejb",
            "com.ramdroid.appquarantinepro", "com.jrummy.apps.root.browser", "re.frida.server",
            "com.saurik.substrate", "de.robv.android.xposed.installer"
        ];
        
        if (rootApps.includes(pkgName)) {
            console.log("🚫 Blocked root app: " + pkgName);
            throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new();
        }
        return this.getPackageInfo.call(this, pkgName, flags);
    };
    
    PackageManager.getInstalledPackages.implementation = function(flags) {
        var list = this.getInstalledPackages.call(this, flags);
        var filteredList = Java.use("java.util.ArrayList").$new();
        
        for (var i = 0; i < list.size(); i++) {
            var packageInfo = list.get(i);
            var packageName = packageInfo.packageName.value;
            
            var isRootApp = packageName.includes("supersu") || 
                           packageName.includes("superuser") ||
                           packageName.includes("magisk") ||
                           packageName.includes("frida") ||
                           packageName.includes("xposed") ||
                           packageName.includes("root") ||
                           packageName.includes("busybox") ||
                           packageName.includes("substrate");
            
            if (!isRootApp) {
                filteredList.add(packageInfo);
            }
        }
        return filteredList;
    };
    
    console.log("✅ Root detection bypass completed");
    
    // ==================== EMULATOR DETECTION BYPASS ====================
    
    // 1. SYSTEM PROPERTIES BYPASS
    var SystemProperties = Java.use("android.os.SystemProperties");
    
    SystemProperties.get.overload('java.lang.String').implementation = function(key) {
        var emulatorProps = {
            "ro.kernel.qemu": "0",
            "ro.boot.qemu": "0", 
            "ro.hardware": "qcom",
            "ro.product.cpu.abi": "arm64-v8a",
            "ro.build.tags": "release-keys",
            "ro.build.type": "user",
            "ro.debuggable": "0",
            "ro.secure": "1",
            "ro.boot.serialno": "R58M70ZM9SP",
            "ro.serialno": "R58M70ZM9SP",
            "qemu.gles": "0",
            "qemu.hw.mainkeys": "0",
            "init.svc.adbd": "stopped",
            "init.svc.debuggerd": "running"
        };
        
        if (emulatorProps[key] !== undefined) {
            return emulatorProps[key];
        }
        return this.get.call(this, key);
    };
    
    // 2. TELEPHONY MANAGER BYPASS
    var TelephonyManager = Java.use("android.telephony.TelephonyManager");
    
    TelephonyManager.getDeviceId.implementation = function() { return "357175080448741"; };
    TelephonyManager.getImei.implementation = function() { return "357175080448741"; };
    TelephonyManager.getSimOperatorName.implementation = function() { return "Airtel"; };
    TelephonyManager.getNetworkOperatorName.implementation = function() { return "Airtel"; };
    TelephonyManager.getSimCountryIso.implementation = function() { return "in"; };
    TelephonyManager.getLine1Number.implementation = function() { return "+919876543210"; };
    
    // 3. SETTINGS SECURE BYPASS
    var SettingsSecure = Java.use("android.provider.Settings$Secure");
    
    SettingsSecure.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, key) {
        if (key === "android_id") return "8f16e67e7a8b4d8a";
        if (key === "adb_enabled") return "0";
        if (key === "development_settings_enabled") return "0";
        return this.getString.call(this, cr, key);
    };
    
    // 4. DEBUG CHECK BYPASS
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function() { return false; };
    Debug.waitingForDebugger.implementation = function() { return false; };
    
    var ActivityManager = Java.use("android.app.ActivityManager");
    ActivityManager.isUserAMonkey.implementation = function() { return false; };
    
    // 5. SENSOR MANAGER BYPASS
    var SensorManager = Java.use("android.hardware.SensorManager");
    
    SensorManager.getSensorList.implementation = function(type) {
        var list = this.getSensorList.call(this, type);
        var filteredList = Java.use("java.util.ArrayList").$new();
        
        for (var i = 0; i < list.size(); i++) {
            var sensor = list.get(i);
            var sensorName = sensor.getName().toLowerCase();
            
            if (!sensorName.includes("goldfish") && 
                !sensorName.includes("android") &&
                !sensorName.includes("emulator")) {
                filteredList.add(sensor);
            }
        }
        return filteredList;
    };
    
    console.log("✅ Emulator detection bypass completed");
    
    // ==================== ADVANCED DETECTION BYPASS ====================
    
    // 1. REFLECTION BASED DETECTION BYPASS
    var System = Java.use("java.lang.System");
    
    var getProperty = System.getProperty.overload('java.lang.String');
    getProperty.implementation = function(key) {
        if (key === "java.vm.name") return "Dalvik";
        if (key === "java.vendor") return "The Android Project"; 
        if (key === "java.runtime.name") return "Android Runtime";
        return getProperty.call(this, key);
    };
    
    // 2. NATIVE LIBRARY CHECK BYPASS
    try {
        var SystemLoadLibrary = Java.use("java.lang.System");
        SystemLoadLibrary.loadLibrary.implementation = function(libname) {
            if (libname.includes("frida") || libname.includes("substrate") || libname.includes("xposed")) {
                console.log("🚫 Blocked native library: " + libname);
                return;
            }
            return this.loadLibrary.call(this, libname);
        };
    } catch(e) {}
    
    // 3. SAFETYNET & PLAY INTEGRITY BYPASS
    try {
        var SafetyNetClass = Java.use("com.google.android.gms.safetynet.SafetyNetClient");
        SafetyNetClass.attest.implementation = function(nonce) {
            console.log("✅ SafetyNet attestation bypassed");
            return Java.use("com.google.android.gms.tasks.Tasks").await(Java.use("com.google.android.gms.tasks.Task").$new());
        };
    } catch(e) {
        console.log("⚠️ SafetyNet class not found");
    }
    
    // 4. ROOT BEER & LIBRARY DETECTION BYPASS
    try {
        // RootBeer Library bypass
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        if (RootBeer) {
            RootBeer.isRooted.implementation = function() { return false; };
            RootBeer.detectRootManagementApps.implementation = function() { return false; };
            RootBeer.detectPotentiallyDangerousApps.implementation = function() { return false; };
            console.log("✅ RootBeer library bypassed");
        }
    } catch(e) {}
    
    // 5. XPOSED/FRAMEWORK DETECTION BYPASS
    try {
        var XposedHelpers = Java.use("de.robv.android.xposed.XposedHelpers");
        XposedHelpers.findField.implementation = function() { 
            throw Java.use("java.lang.NoSuchFieldException").$new(); 
        };
    } catch(e) {}
    
    console.log("🎯 ULTIMATE BYPASS COMPLETED! Root + Emulator detection fully hooked");
});

// ==================== NATIVE LEVEL BYPASS ====================

// 1. FILE OPERATIONS HOOK
Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
    onEnter: function(args) {
        this.path = Memory.readCString(args[0]);
    },
    onLeave: function(retval) {
        var blocked = ["su", "busybox", "magisk", "frida", "xposed", "qemu", "genymotion"];
        for (var i = 0; i < blocked.length; i++) {
            if (this.path.includes(blocked[i])) {
                retval.replace(ptr(0x0));
                break;
            }
        }
    }
});

// 2. SYSTEM PROPERTIES HOOK
Interceptor.attach(Module.findExportByName("libc.so", "__system_property_get"), {
    onEnter: function(args) {
        this.name = Memory.readCString(args[0]);
    },
    onLeave: function(retval) {
        if (this.name.includes("qemu") || this.name.includes("emu") || this.name.includes("debug")) {
            Memory.writeCString(retval, "0");
        }
    }
});

// 3. PROCESS HOOK
Interceptor.attach(Module.findExportByName("libc.so", "popen"), {
    onEnter: function(args) {
        this.command = Memory.readCString(args[0]);
    },
    onLeave: function(retval) {
        if (this.command.includes("su") || this.command.includes("busybox") || this.command.includes("which su")) {
            retval.replace(ptr(0x0));
        }
    }
});

console.log("🔧 Native hooks installed successfully");