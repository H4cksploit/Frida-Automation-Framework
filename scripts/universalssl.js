Java.perform(function() {
    console.log("[+] Hooking SSL Libraries...");

    // Conscrypt SSL Fix
    var ActiveSession = Java.use('com.android.org.conscrypt.ActiveSession');
    ActiveSession.checkPeerCertificatesPresent.implementation = function () {
        console.log("[+] Bypassed checkPeerCertificatesPresent()");
        return;
    };

    // Bypass TrustManager (Java Default SSL Validation)
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
        console.log("[+] Bypassing TrustManagerImpl.verifyChain()");
        return untrustedChain;
    };

    // Bypass OkHttp SSL Pinning
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
        console.log("[+] Bypassed OkHttp SSL Pinning for: " + hostname);
        return;
    };

    // WebView SSL Error Bypass
    var WebViewClient = Java.use('android.webkit.WebViewClient');
    WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
        console.log("[+] Bypassed WebView SSL Error");
        handler.proceed();
    };
});
