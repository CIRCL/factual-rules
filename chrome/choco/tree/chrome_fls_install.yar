rule chrome_fls_install {
	meta:
		description = "Auto generation for chrome"
		author = "David Cruciani"
		date = "2021-10-28"
		versionApp = "95.0.4638.54"
		uuid = "f9e6e3e9-7157-4b5d-950d-f629f404e03a"
		uninstaller = "choco"
	strings: 
		$s0 = /chrome\.dll/
		$s1 = /chrome\.dll\.sig/
		$s2 = /chrome\.exe\.sig/
		$s3 = /chrome\_100\_percent\.pak/
		$s4 = /chrome\_200\_percent\.pak/
		$s5 = /chrome\_elf\.dll/
		$s6 = /chrome\_pwa\_launcher\.exe/
		$s7 = /chrome\.7z/
		$s8 = /chrome\.exe/
		$s9 = /chrome\.VisualElementsManifest\.xml/
		$s10 = /chrome\_proxy\.exe/
		$s11 = /chrome\_installer\.exe/
		$s12 = /com\.microsoft\.defender\.be\.chrome\.json/
		$s13 = /googlechromestandaloneenterprise64\.msi/
		$s14 = /chrome\_installer\.log/
		$s15 = /chrome\.browser/
		$s16 = /backstack\-chrome\-breadcrumb\-template\.html/
		$s17 = /backstack\-chrome\-breadcrumb\-vm\.js/
		$s18 = /close\-chrome\-breadcrumb\-template\.html/
		$s19 = /close\-chrome\-breadcrumb\-vm\.js/
		$s20 = /oobe\-chrome\-breadcrumb\-template\.html/
		$s21 = /oobe\-chrome\-breadcrumb\-vm\.js/
		$s22 = /oobe\-chrome\-contentview\-template\.html/
		$s23 = /oobe\-chrome\-contentview\-vm\.js/
		$s24 = /oobe\-chrome\-footer\-template\.html/
		$s25 = /oobe\-chrome\-footer\-vm\.js/
		$s26 = /CHROME\.EXE\-5A1054AF\.pf/
		$s27 = /CHROME\.EXE\-5A1054B0\.pf/
		$s28 = /CHROME\.EXE\-5A1054B1\.pf/
		$s29 = /CHROME\.EXE\-5A1054B6\.pf/
		$s30 = /CHROME\.EXE\-5A1054B7\.pf/
		$s31 = /CHROME\_INSTALLER\.EXE\-AE96886E\.pf/
	condition:
		 ext_var of ($s*)
}