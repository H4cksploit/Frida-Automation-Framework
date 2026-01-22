Java.perform(function () {
    // Locate the BuildConfig class
    var BuildConfig = Java.use("com.softpos.pin.BuildConfig");

    // Disable anti-debugging and restrictive flags
    BuildConfig.DEBUGGER_CHECK.value = false;
    console.log("[+] Disabled Debugger Check");

    BuildConfig.ENABLE_DEVELOPER_OPT_CHECK.value = false;
    console.log("[+] Disabled Developer Options Check");

    BuildConfig.ENABLE_SCREEN_CAPTURE.value = true;
    console.log("[+] Enabled Screen Capture");

    BuildConfig.FILE_LOGGING.value = true;
    BuildConfig.FILE_LOGGING_ISEXTERNAL.value = true;
    console.log("[+] Enabled File Logging");

    // Ensure logging is enabled for debugging
    BuildConfig.SHOW_LOG.value = true;
    BuildConfig.SHOW_SENSTIVE_LOG.value = true;
    console.log("[+] Enabled Logging (Sensitive and General)");

    // Handle potential static block behavior
    try {
        var LupusClass = Java.use("vela.fornax.lupus.nvnnnnn");
        console.log("[*] Detected and loaded 'vela.fornax.lupus.nvnnnnn' class.");
    } catch (error) {
        console.log("[!] 'vela.fornax.lupus.nvnnnnn' class not found or not defined. Skipping.");
    }

    console.log("[*] BuildConfig modifications applied successfully.");
});
