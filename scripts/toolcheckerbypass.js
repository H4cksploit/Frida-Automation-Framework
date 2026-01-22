Java.perform(function () {
    var RootBeerNative = Java.use("com.scottyab.rootbeer.RootBeerNative");

    // Hook the checkForRoot method
    RootBeerNative.checkForRoot.implementation = function (args) {
        console.log("[+] Bypassing RootBeer root check...");
        return 0;  // Always return 0 (no root detected)
    };
});

Java.perform(function () {
    console.log("[Frida] Hooking RootBeerNative for Root Bypass...");

    var System = Java.use("java.lang.System");

    // ✅ 1️⃣ Allow `toolChecker` to load but log it
    System.loadLibrary.overload("java.lang.String").implementation = function (lib) {
        console.log("[Frida] Attempting to load: " + lib);
        return this.loadLibrary.call(this, lib);
    };

    // ✅ 2️⃣ Patch RootBeerNative checkForRoot() to always return 0
    var RootBeerNative = Java.use("com.scottyab.rootbeer.RootBeerNative");
    RootBeerNative.checkForRoot.implementation = function (args) {
        console.log("[Frida] checkForRoot() called. Returning 0 (No root detected).");
        return 0;  // Always return no root detected
    };

    console.log("[Frida] Root detection bypass is active! 🎉");
});

Interceptor.attach(Module.findExportByName(null, "checkForRoot"), {
    onEnter: function (args) {
        console.log("[Frida] Native checkForRoot() called. Bypassing...");
        this.return_value = ptr(0);
    },
    onLeave: function (retval) {
        retval.replace(0);
        console.log("[Frida] Native checkForRoot() patched!");
    }
});
