rule firefox_fls_uninstall {
	meta:
		description = "Auto generation for firefox"
		author = "David Cruciani"
		date = "2021-11-18"
		versionApp = "94.0"
		uuid = "cadf132f-989c-4feb-9fb6-54197c1dc347"
		uninstaller = "choco"
	strings: 
		$s0 = /firefox\.browser/
		$s1 = /FIREFOX SETUP 94\.0\.EXE\-819E4A89\.pf/
		$s2 = /FIREFOX\.EXE\-A606B53C\.pf/
		$s3 = /firefox\.exe/
		$s4 = /firefox\.exe\.sig/
		$s5 = /firefox\.VisualElementsManifest\.xml/
	condition:
		 ext_var of ($s*)
}