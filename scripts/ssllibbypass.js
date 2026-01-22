Interceptor.attach(Module.findExportByName(null, "SSL_get_verify_result"), {
    onEnter: function(args) {
        console.log("[+] Intercepted SSL_get_verify_result");
    },
    onLeave: function(retval) {
        console.log("[+] SSL verification bypassed!");
        retval.replace(0);
    }
});
