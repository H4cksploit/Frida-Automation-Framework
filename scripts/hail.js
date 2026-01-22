Java.perform(function() {
    var ActiveSession = Java.use("com.android.org.conscrypt.ActiveSession");

    // Choose one of the overloads based on the parameters you need
    var checkMethod = ActiveSession.check.overload('java.lang.String', 'java.util.List');
    
    checkMethod.implementation = function(arg0, arg1) {
        console.log("check() called with arguments: " + arg0 + ", " + arg1);
        
        // You can modify the arguments or return value here if needed
        return this.check(arg0, arg1);
    };
});
