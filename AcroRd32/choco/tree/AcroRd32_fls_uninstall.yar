rule AcroRd32_fls_uninstall {
	meta:
		description = "Auto generation for AcroRd32"
		author = "David Cruciani"
		date = "2021-11-18"
		versionApp = "21.7.20099.454979"
		uuid = "e2c95537-d447-4427-afc0-54bcbe8be2f0"
		uninstaller = "choco"
	strings: 
		$s0 = /\{7C5A40EF\-A0FB\-4BFC\-874A\-C0F2E0B9FA8E\}\_Adobe\_Acrobat Reader DC\_Reader\_AcroRd32\_exe/
		$s1 = /acrord32\_sbx/
		$s2 = /acrord32\_super\_sbx/
		$s3 = /ACRORD32\.EXE\-ACF2947D\.pf/
		$s4 = /ACRORD32\.EXE\-ACF2947E\.pf/
	condition:
		 ext_var of ($s*)
}