rule firefox_fls_install {
	meta:
		description = "Auto generation for firefox"
		author = "David Cruciani"
		date = "2021-11-18"
		versionApp = "94.0"
		uuid = "0de5c454-f3f2-4ce2-a37d-e8f3a03f9fdb"
		uninstaller = "choco"
	strings: 
		$s0 = /firefox\.exe/
		$s1 = /firefox\.exe\.sig/
		$s2 = /firefox\.VisualElementsManifest\.xml/
		$s3 = /firefox\.browser/
		$s4 = /FIREFOX SETUP 94\.0\.EXE\-819E4A89\.pf/
		$s5 = /FIREFOX\.EXE\-A606B53C\.pf/
	condition:
		 ext_var of ($s*)
}