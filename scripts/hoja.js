setTimeout(function() {
    Java.perform(function () {
        console.log("Starting Enhanced SSL Pinning Bypass Script with Conscrypt Patch");

        // --- Original OkHTTP CertificatePinner hooks ---
        var okhttp3_CertificatePinner_class = null;
        try {
            okhttp3_CertificatePinner_class = Java.use('okhttp3.CertificatePinner');    
        } catch (err) {
            console.log('[-] OkHTTPv3 CertificatePinner class not found. Skipping.');
            okhttp3_CertificatePinner_class = null;
        }

        if(okhttp3_CertificatePinner_class != null) {
            try {
                okhttp3_CertificatePinner_class.check.overload('java.lang.String', 'java.util.List').implementation = function (str, list) {
                    console.log('[+] Bypassing OkHTTPv3 check with List: ' + str);
                    return true;
                };
                console.log('[+] Loaded OkHTTPv3 hook 1');
            } catch(err) {
                console.log('[-] Skipping OkHTTPv3 hook 1');
            }

            try {
                okhttp3_CertificatePinner_class.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (str, cert) {
                    console.log('[+] Bypassing OkHTTPv3 check with Certificate: ' + str);
                    return true;
                };
                console.log('[+] Loaded OkHTTPv3 hook 2');
            } catch(err) {
                console.log('[-] Skipping OkHTTPv3 hook 2');
            }

            try {
                okhttp3_CertificatePinner_class.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (str, cert_array) {
                    console.log('[+] Bypassing OkHTTPv3 check with Certificate array: ' + str);
                    return true;
                };
                console.log('[+] Loaded OkHTTPv3 hook 3');
            } catch(err) {
                console.log('[-] Skipping OkHTTPv3 hook 3');
            }

            try {
                okhttp3_CertificatePinner_class['check$okhttp'].implementation = function (str, obj) {
                    console.log('[+] Bypassing OkHTTPv3 check (4.2+): ' + str);
                };
                console.log('[+] Loaded OkHTTPv3 hook 4 (4.2+)');
            } catch(err) {
                console.log('[-] Skipping OkHTTPv3 hook 4 (4.2+)');
            }
        }

        // --- Additional Conscrypt and ActiveSession Patching ---
        var ActiveSession = Java.use("com.android.org.conscrypt.ActiveSession");
        if (ActiveSession) {
            try {
                ActiveSession.checkPeerCertificatesPresent.implementation = function() {
                    console.log("[+] Bypassing checkPeerCertificatesPresent in ActiveSession");
                    return; // Skip actual check, allow connection
                };
                console.log("[+] Loaded ActiveSession SSL check bypass");
            } catch(err) {
                console.log("[-] Skipping ActiveSession SSL check bypass");
            }
        }

        // --- Updated AndroidSocketAdapter Checks ---
        var AndroidSocketAdapter = Java.use("okhttp3.internal.platform.android.AndroidSocketAdapter");
        
        if (AndroidSocketAdapter) {
            try {
                if (AndroidSocketAdapter.getAlpnSelectedProtocol) {
                    AndroidSocketAdapter.getAlpnSelectedProtocol.implementation = function(socket) {
                        console.log("[+] Bypassing getAlpnSelectedProtocol");
                        return null;
                    };
                }
            } catch(err) {
                console.log("[-] Skipping getAlpnSelectedProtocol bypass due to error.");
            }

            try {
                if (AndroidSocketAdapter.setUseSessionTickets) {
                    AndroidSocketAdapter.setUseSessionTickets.implementation = function(socket, useSessionTickets) {
                        console.log("[+] Bypassing setUseSessionTickets");
                        this.setUseSessionTickets(socket, true);
                    };
                }
            } catch(err) {
                console.log("[-] Skipping setUseSessionTickets bypass due to error.");
            }

            try {
                if (AndroidSocketAdapter.setHostname) {
                    AndroidSocketAdapter.setHostname.implementation = function(socket, hostname) {
                        console.log("[+] Bypassing setHostname with hostname: " + hostname);
                        this.setHostname(socket, hostname);
                    };
                }
            } catch(err) {
                console.log("[-] Skipping setHostname bypass due to error.");
            }
        }

        console.log("Enhanced SSL Pinning Bypass Script with Conscrypt Patch Loaded Successfully");
    });
}, 0);
