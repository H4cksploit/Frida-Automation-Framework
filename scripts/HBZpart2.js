Java.perform(function () {
    const Log = Java.use('android.util.Log');
    const System = Java.use('java.lang.System');

    try {
        // Hook Frida detection methods
        const targetClass = 'com.codename1.impl.android.j';
        const cls = Java.use(targetClass);

        if (cls.b) {
            cls.b.implementation = function () {
                Log.i("FridaBypass", "Bypassed Frida detection method b");
                return false;
            };
        }

        if (cls.d) {
            cls.d.implementation = function () {
                Log.i("FridaBypass", "Bypassed Frida detection method d");
                return false;
            };
        }

        if (cls.e) {
            cls.e.implementation = function () {
                Log.i("FridaBypass", "Bypassed Frida detection method e");
                return false;
            };
        }

        if (cls.f) {
            cls.f.implementation = function () {
                Log.i("FridaBypass", "Bypassed Frida detection method f");
                return false;
            };
        }

        if (cls.g) {
            cls.g.implementation = function (context) {
                Log.i("FridaBypass", "Bypassed Frida detection method g");
            };
        }

        // Hook System.exit to prevent app exit
        System.exit.overload('int').implementation = function (code) {
            Log.i("FridaBypass", "Prevented System.exit with code: " + code);
        };

        Log.i("FridaBypass", "Frida detection methods patched successfully.");
    } catch (e) {
        Log.e("FridaBypass", "Error patching Frida detection: " + e);
    }

    try {
        // Hook RootBeer methods
        const RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');

        RootBeer.isRooted.implementation = function () {
            Log.i("FridaBypass", "Bypassed RootBeer isRooted method");
            return false;
        };

        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function () {
            Log.i("FridaBypass", "Bypassed RootBeer isRootedWithoutBusyBoxCheck method");
            return false;
        };

        Log.i("FridaBypass", "RootBeer root detection methods patched successfully.");
    } catch (e) {
        Log.e("FridaBypass", "Error patching RootBeer detection: " + e);
    }
});
