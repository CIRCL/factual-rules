rule notepad++_uninstall {
	meta:
		description = "Auto generation for notepad++"
		author = "David Cruciani"
		date = "2022-01-13"
		versionApp = "8.2"
		uuid = "281fcba8-6108-4329-91df-0c4afe8131f1"
		uninstaller = "choco"
	strings: 
		$s0 = /NOTEPAD\+\+\.EXE/
		$s1 = /notepad\+\+\.exe/
		$s2 = /notepad\+\+/
	condition:
		 ext_var of ($s*)
}