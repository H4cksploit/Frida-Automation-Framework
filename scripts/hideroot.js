Java.perform(function () {
    var rootChecks = [
        "java.lang.System.getenv",    // Checks environment variables
        "java.io.File.exists",        // Checks for root-related files
        "java.lang.Runtime.exec",     // Executes shell commands
        "android.os.Build.TAGS",      // Looks for "test-keys"
        "android.os.SystemProperties.get", // System properties
        "java.lang.Class.forName"     // Loads root-detection classes
    ];

    function hookMethod(className, methodName, returnValue) {
        try {
            var targetClass = Java.use(className);
            targetClass[methodName].implementation = function () {
                console.log("[Frida] Bypassing " + className + "." + methodName);
                return returnValue; 
            };
        } catch (err) {
            console.log("[Frida] Failed to hook: " + className + "." + methodName);
        }
    }

    // 1️⃣ Prevent build tags from exposing root
    hookMethod("android.os.Build", "TAGS", null);

    // 2️⃣ Prevent apps from checking system properties
    Java.use("android.os.SystemProperties").get.overload("java.lang.String").implementation = function (key) {
        if (key.includes("ro.build.tags") || key.includes("ro.secure")) {
            console.log("[Frida] Blocking system property: " + key);
            return "";
        }
        return this.get.call(this, key);
    };

    // 3️⃣ Prevent access to root binaries
    Java.use("java.io.File").exists.implementation = function () {
        var path = this.getAbsolutePath();
        if (path.includes("su") || path.includes("busybox") || path.includes("magisk")) {
            console.log("[Frida] Hiding root file: " + path);
            return false;
        }
        return this.exists.call(this);
    };

    // 4️⃣ Prevent command execution revealing root
    Java.use("java.lang.Runtime").exec.overload("[Ljava.lang.String;").implementation = function (cmd) {
        console.log("[Frida] Blocking exec() call: " + cmd);
        return null;
    };
});
