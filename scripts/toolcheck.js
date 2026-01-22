Java.perform(function () {
    console.log("[Frida] Hooking RootBeerNative for Root Bypass...");

    var System = Java.use("java.lang.System");

    // ✅ 1️⃣ Prevent `toolChecker` from being loaded OR return success
    System.loadLibrary.overload("java.lang.String").implementation = function (lib) {
        console.log("[Frida] Attempting to load: " + lib);
        if (lib === "toolChecker") {
            console.log("[Frida] Bypassing toolChecker loading.");
            return; // Prevent actual loading
        }
        return this.loadLibrary.call(this, lib);
    };

    // ✅ 2️⃣ Patch RootBeerNative's `checkForRoot()` to always return 0
    var RootBeerNative = Java.use("com.scottyab.rootbeer.RootBeerNative");
    RootBeerNative.checkForRoot.implementation = function (args) {
        console.log("[Frida] checkForRoot() called. Returning 0 (No root detected).");
        return 0;  // Always return no root detected
    };

    console.log("[Frida] Root detection bypass is active! 🎉");
});
