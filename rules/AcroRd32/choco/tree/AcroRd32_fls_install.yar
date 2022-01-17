rule AcroRd32_fls_install {
	meta:
		description = "Auto generation for AcroRd32"
		author = "David Cruciani"
		date = "2021-11-18"
		versionApp = "21.7.20099.454979"
		uuid = "2fa17cae-adb2-4fe7-8678-3767546f339f"
		uninstaller = "choco"
	strings: 
		$s0 = /AcroRd32\.dll/
		$s1 = /AcroRd32\.exe/
		$s2 = /AcroRd32Info\.exe/
		$s3 = /AcroRd32Res\.dll/
		$s4 = /\{7C5A40EF\-A0FB\-4BFC\-874A\-C0F2E0B9FA8E\}\_Adobe\_Acrobat Reader DC\_Reader\_AcroRd32\_exe/
		$s5 = /acrord32\_sbx/
		$s6 = /acrord32\_super\_sbx/
		$s7 = /acrord32res\.dll/
		$s8 = /ACRORD32\.EXE\-ACF2947D\.pf/
		$s9 = /ACRORD32\.EXE\-ACF2947E\.pf/
	condition:
		 ext_var of ($s*)
}