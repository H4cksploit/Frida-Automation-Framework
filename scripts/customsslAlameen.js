Java.perform(function() {
    console.log("Starting SSL Pinning Bypass Script");

    // Target the AndroidSocketAdapter class specifically
    var AndroidSocketAdapter = Java.use("okhttp3.internal.platform.android.AndroidSocketAdapter");

    // Override getAlpnSelectedProtocol to bypass ALPN protocol checks
    AndroidSocketAdapter.getAlpnSelectedProtocol.implementation = function(socket) {
        console.log("[+] Bypassing getAlpnSelectedProtocol");
        return null; // Returning null to avoid SSL verification issues
    };

    // Override setUseSessionTickets to allow session tickets
    AndroidSocketAdapter.setUseSessionTickets.implementation = function(socket, useSessionTickets) {
        console.log("[+] Bypassing setUseSessionTickets");
        this.setUseSessionTickets(socket, true); // Enforcing use of session tickets
    };

    // Override setHostname to bypass hostname verification
    AndroidSocketAdapter.setHostname.implementation = function(socket, hostname) {
        console.log("[+] Bypassing setHostname with hostname: " + hostname);
        this.setHostname(socket, hostname); // No-op or set to desired hostname
    };

    // Hook the TrustManager to disable certificate verification
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    X509TrustManager.checkServerTrusted.implementation = function(chain, authType) {
        console.log("[+] Bypassing X509TrustManager checkServerTrusted");
        // No-op: allow all certificates
    };

    // Hook OkHttpClient.Builder to bypass SSL verification
    var OkHttpClientBuilder = Java.use("okhttp3.OkHttpClient$Builder");
    OkHttpClientBuilder.sslSocketFactory.overload("javax.net.ssl.SSLSocketFactory", "javax.net.ssl.X509TrustManager").implementation = function(factory, trustManager) {
        console.log("[+] Bypassing OkHttpClient SSL Socket Factory");
        return this.sslSocketFactory(factory, trustManager); // Set a trusting TrustManager
    };

    // Hook any remaining SSL checks that may occur through internal validation methods
    var Conscrypt = Java.use("com.android.org.conscrypt.OpenSSLX509CertificateFactory");
    Conscrypt.verifyChain.implementation = function(chain, trustAnchor, ocspData, tlsSctData) {
        console.log("[+] Bypassing Conscrypt verifyChain");
        return chain; // Return the chain as trusted
    };

    console.log("SSL Pinning Bypass Script Loaded Successfully");
});
