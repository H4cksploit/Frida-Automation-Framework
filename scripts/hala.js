Java.perform(function() {
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.implementation = function() {
        console.log('Bypassing SSL pinning!');
        return; // Bypass logic
    };
});