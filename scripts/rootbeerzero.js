Java.perform(function () {
    console.log("[Frida] Hooking RootBeerNative Bypass...");

    // 1️⃣ Prevent RootBeer from loading its native library
    var System = Java.use("java.lang.System");
    System.loadLibrary.implementation = function (lib) {
        console.log("[Frida] Trying to load library: " + lib);
        if (lib === "toolChecker") {
            console.log("[Frida] Blocking RootBeer native library...");
            return;
        }
        return this.loadLibrary.call(this, lib);
    };

    // 2️⃣ Bypass RootBeerNative checkForRoot
    var RootBeerNative = Java.use("com.scottyab.rootbeer.RootBeerNative");
    RootBeerNative.checkForRoot.implementation = function (args) {
        console.log("[Frida] RootBeer checkForRoot() called. Returning 0...");
        return 0;  // Return 0 to indicate no root detected
    };

    console.log("[Frida] RootBeerNative bypass applied successfully!");
});
