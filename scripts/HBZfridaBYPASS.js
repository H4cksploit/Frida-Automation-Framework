Java.perform(function () {
    const Log = Java.use('android.util.Log');
    const System = Java.use('java.lang.System');

    // Bypass method b
    const FridaUtil = Java.use('com.codename1.impl.android.j');
    FridaUtil.b.implementation = function () {
        Log.i("FridaBypass", "Bypassed method b");
        return false;
    };

    // Bypass method d
    FridaUtil.d.implementation = function () {
        Log.i("FridaBypass", "Bypassed method d");
        return false;
    };

    // Bypass method e
    FridaUtil.e.implementation = function () {
        Log.i("FridaBypass", "Bypassed method e");
        return false;
    };

    // Bypass method f
    FridaUtil.f.implementation = function () {
        Log.i("FridaBypass", "Bypassed method f");
        return false;
    };

    // Prevent System.exit(0) in method g
    FridaUtil.g.implementation = function (context) {
        Log.i("FridaBypass", "Bypassed method g - preventing app exit");
    };

    // Optionally hook System.exit(0) to ensure it doesn't terminate the app
    System.exit.overload('int').implementation = function (code) {
        Log.i("FridaBypass", "Prevented System.exit with code: " + code);
    };

    Log.i("FridaBypass", "All Frida detection methods bypassed!");
});
