Java.perform(function() {
    // Hook the file detection method
    var fridaDetection = Java.use('ws.krlp.FridaDetection');
    fridaDetection.checkForFridaFiles.implementation = function() {
        console.log("Bypassed Frida file detection");
        return false; // Always return false to bypass the check
    };

    // Hook the port detection method
    fridaDetection.checkForFridaPorts.implementation = function() {
        console.log("Bypassed Frida port detection");
        return false; // Always return false to bypass the check
    };

    // Hook the process detection method
    fridaDetection.checkForFridaServerProcesses.implementation = function() {
        console.log("Bypassed Frida process detection");
        return false; // Always return false to bypass the check
    };
});
