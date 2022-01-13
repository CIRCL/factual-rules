rule notepad++_fls_install {
	meta:
		description = "Auto generation for notepad++"
		author = "David Cruciani"
		date = "2022-01-13"
		versionApp = "8.2"
		uuid = "cbe5e9c7-6058-46b9-a096-61b550e6dc27"
		uninstaller = "choco"
	strings: 
		$s0 = /notepad\+\+\.exe/
		$s1 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_Notepad\+\+\_notepad\+\+\_exe/
		$s2 = /NOTEPAD\+\+\.EXE\-72A5A810\.pf/
	condition:
		 ext_var of ($s*)
}