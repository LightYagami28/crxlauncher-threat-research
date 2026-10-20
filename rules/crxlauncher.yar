/*
    YARA Rule: ChromeExt_CRXLauncher_Dropper
    Description: Detects CRXLauncher Chrome Extension MV3 dropper and CEVM components
    Reference: https://github.com/LightYagami28/crxlauncher-threat-research
*/

rule ChromeExt_CRXLauncher_Dropper {
    meta:
        description = "Detects CRXLauncher MV3 Dropper and CEVM Emulator components"
        author = "Security Research Team"
        date = "2026-10-20"
        severity = "CRITICAL"
        extension_id = "kiilhncajadbgbmdbdcopdpnmdhlbdle"
        tlp = "CLEAR"

    strings:
        // Window messaging namespaces
        $s1 = "__crxlauncher_window_communication" ascii wide
        $s2 = "__crxlauncher_runtime_message__" ascii wide
        $s3 = "pre_cl_loglevel__v3" ascii wide
        
        // Trusted Types neutralization signature
        $s4 = "window.trustedTypes?.createPolicy("default"" ascii wide
        
        // Virtual Chrome environment methods
        $s5 = "main: get sandbox content script" ascii wide
        $s6 = "main: get sandbox data" ascii wide
        
        // Telemetry endpoint & credentials
        $s7 = "G-Z14126F651" ascii wide
        $s8 = "NqpDuhxQTVSqAVkEgU4nPQ" ascii wide

        // Dynamic execution in sandbox
        $s9 = "new Function(a.js)()" ascii wide

    condition:
        3 of ($s*) or all of ($s1, $s2, $s4) or all of ($s7, $s8)
}
