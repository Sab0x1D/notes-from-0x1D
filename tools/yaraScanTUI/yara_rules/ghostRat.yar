// ---
// name: "GhostRAT"
// family: "GhostRAT"
// tags: ["rat","remote"]
// author: "Sab0x1D"
// last_updated: "2025-11-06"
// tlp: "CLEAR"
// ---

rule GhostRAT
{
meta:
	description = "Detects GhostRAT malware"
strings: 
    $str1 = "WinSta0\\Default"
	$str2 = "GetClipboardData"
	$str3 = /(%)s\\shell\\open\\command/
	$ip1 = "129.226.170.223"
	$str4 = "ZhuDongFangYu.exe"
	$str5 = "Software\\Tencent\\Plugin\\VAS"
	$str6 = "UnThreat.exe" 
	$str7 = "LogonTrigger"
	$str8 = "AdjustTokenPrivileges"
condition:
  4 of them
}

