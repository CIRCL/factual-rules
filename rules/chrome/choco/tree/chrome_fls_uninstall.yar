rule chrome_fls_uninstall {
	meta:
		description = "Auto generation for chrome"
		author = "David Cruciani"
		date = "2021-10-28"
		versionApp = "95.0.4638.54"
		uuid = "e7ce6d76-3f13-4490-a864-1f7d16d83016"
		uninstaller = "choco"
	strings: 
		$s0 = /chrome\_100\_percent\.pak/
		$s1 = /chrome\_200\_percent\.pak/
		$s2 = /chrome\.dll/
		$s3 = /chrome\_elf\.dll/
		$s4 = /chrome\_pwa\_launcher\.exe/
		$s5 = /chrome\.exe\.sig/
		$s6 = /chrome\.dll\.sig/
		$s7 = /chrome\.7z/
		$s8 = /chrome\.exe/
		$s9 = /chrome\.VisualElementsManifest\.xml/
		$s10 = /chrome\_proxy\.exe/
		$s11 = /chrome\_installer\.exe/
		$s12 = /com\.microsoft\.defender\.be\.chrome\.json/
		$s13 = /chrome\_installer\.log/
		$s14 = /chrome\.browser/
		$s15 = /backstack\-chrome\-breadcrumb\-template\.html/
		$s16 = /backstack\-chrome\-breadcrumb\-vm\.js/
		$s17 = /close\-chrome\-breadcrumb\-template\.html/
		$s18 = /close\-chrome\-breadcrumb\-vm\.js/
		$s19 = /oobe\-chrome\-breadcrumb\-template\.html/
		$s20 = /oobe\-chrome\-breadcrumb\-vm\.js/
		$s21 = /oobe\-chrome\-contentview\-template\.html/
		$s22 = /oobe\-chrome\-contentview\-vm\.js/
		$s23 = /oobe\-chrome\-footer\-template\.html/
		$s24 = /oobe\-chrome\-footer\-vm\.js/
		$s25 = /CHROME\.EXE\-5A1054AF\.pf/
		$s26 = /CHROME\.EXE\-5A1054B0\.pf/
		$s27 = /CHROME\.EXE\-5A1054B1\.pf/
		$s28 = /CHROME\.EXE\-5A1054B6\.pf/
		$s29 = /CHROME\.EXE\-5A1054B7\.pf/
		$s30 = /CHROME\_INSTALLER\.EXE\-AE96886E\.pf/
	condition:
		 ext_var of ($s*)
}