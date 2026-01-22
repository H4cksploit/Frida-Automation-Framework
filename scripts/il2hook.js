function tryHookOpen() {
    try {
        var openPtr = Module.findExportByName(null, "open");
        if (openPtr !== null) {
            console.log("[+] Hooking open() at: " + openPtr);
            Interceptor.attach(openPtr, {
                onEnter: function(args) {
                    var path = Memory.readUtf8String(args[0]);
                    console.log("[open] Called with path: " + path);
                    if (path.indexOf("/proc/self/maps") !== -1) {
                        console.warn("[open] Redirecting /proc/self/maps -> /dev/null");
                        args[0] = Memory.allocUtf8String("/dev/null");
                    }
                }
            });
        } else {
            console.error("[-] open() not found!");
        }
    } catch (err) {
        console.error("[-] Exception in tryHookOpen: " + err);
    }
}

function tryHookFopen() {
    try {
        var fopenPtr = Module.findExportByName(null, "fopen");
        if (fopenPtr !== null) {
            console.log("[+] Hooking fopen() at: " + fopenPtr);
            Interceptor.attach(fopenPtr, {
                onEnter: function(args) {
                    var path = Memory.readUtf8String(args[0]);
                    console.log("[fopen] Called with path: " + path);
                    if (path.indexOf("/proc/self/status") !== -1) {
                        console.warn("[fopen] Intercepting status read");
                        this.shouldFake = true;
                    }
                },
                onLeave: function(retval) {
                    if (this.shouldFake) {
                        console.log("[fopen] Returning fake TracerPid info");
                        var fakeFile = Memory.allocUtf8String("TracerPid:\t0\n");
                        retval.replace(fakeFile);
                    }
                }
            });
        } else {
            console.error("[-] fopen() not found!");
        }
    } catch (err) {
        console.error("[-] Exception in tryHookFopen: " + err);
    }
}

setTimeout(function () {
    tryHookOpen();
    tryHookFopen();
}, 100); // Slight delay to avoid early crashes
