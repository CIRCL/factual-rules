rule notepad++_install {
	meta:
		description = "Auto generation for notepad++"
		author = "David Cruciani"
		date = "2022-01-13"
		versionApp = "8.2"
		uuid = "847d5aad-4fa4-4b73-9c23-5d71bcd27e86"
		uninstaller = "choco"
	strings: 
		$s0 = /notepad\+\+\.exe/
		$s1 = /notepad\+\+/
		$s2 = /NOTEPAD\+\+\.EXE/
	condition:
		 ext_var of ($s*)
}