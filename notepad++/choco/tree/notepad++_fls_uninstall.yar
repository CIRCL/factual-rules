rule notepad++_fls_uninstall {
	meta:
		description = "Auto generation for notepad++"
		author = "David Cruciani"
		date = "2022-01-13"
		versionApp = "8.2"
		uuid = "3c3a238c-a93c-4367-b4d0-7d9ab4d4c926"
		uninstaller = "choco"
	strings: 
		$s0 = /notepad\+\+\.exe/
		$s1 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_Notepad\+\+\_notepad\+\+\_exe/
		$s2 = /NOTEPAD\+\+\.EXE\-72A5A810\.pf/
	condition:
		 ext_var of ($s*)
}