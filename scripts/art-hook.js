// runtime_trace.js
// Android runtime methods ko trace karne ke liye

Java.perform(function() {
    console.log("[+] Android Runtime Analysis shuru ho rahi hai...");
    
    // Runtime class ko hook karna
    var Runtime = Java.use("java.lang.Runtime");
    
    // exec() method ko hook karna
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        console.log("\n[!] Runtime.exec() called:");
        console.log("    Command: " + cmd);
        var result = this.exec(cmd);
        console.log("    Process created successfully");
        return result;
    };
    
    // exec() with array overload
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmdArray) {
        console.log("\n[!] Runtime.exec(array) called:");
        console.log("    Command Array: " + cmdArray);
        var result = this.exec(cmdArray);
        return result;
    };
    
    // loadLibrary ko track karna
    Runtime.loadLibrary.implementation = function(library) {
        console.log("\n[!] Runtime.loadLibrary() called:");
        console.log("    Library: " + library);
        this.loadLibrary(library);
    };
    
    // freeMemory() ko monitor karna
    Runtime.freeMemory.implementation = function() {
        var memory = this.freeMemory();
        console.log("[*] Free Memory: " + memory + " bytes");
        return memory;
    };
    
    console.log("[✓] All runtime hooks lag gaye hain!");
});

// Process creation ko bhi track karna
var ProcessBuilder = Java.use("java.lang.ProcessBuilder");

ProcessBuilder.start.implementation = function() {
    console.log("\n[!] ProcessBuilder.start() called:");
    var command = this.command();
    console.log("    Command: " + command);
    return this.start();
};