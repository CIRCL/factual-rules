rule git_exe {
	meta:
		description = "Auto generation for git"
		author = "David Cruciani"
		date = "2021-11-18"
		versionApp = ""
		uuid = "65e751fb-4485-4c63-9323-61b56e6d73b5"
		uninstaller = "choco"
	strings: 
		$h = {}
	condition:
		$h
}