rule Example_Loader_Template
{
    meta:
        description = "Replace with what this rule matches"
        author      = "<handle>"
        date        = "YYYY-MM-DD"
        reference   = "https://example.com/writeup"
        attack      = "T1059.001"
        hash_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"

    strings:
        $s1 = "FromBase64String" ascii wide
        $s2 = { 4D 5A ?? ?? 00 00 00 00 }   // PE header pattern

    condition:
        uint16(0) == 0x5A4D and any of ($s*)
}
