
Java.perform(function() {
    var process = Java.use("android.os.Process");
    process.killProcess.implementation = function(pid) {
        console.log("Blocked killProcess attempt");
        return;
    };
});
