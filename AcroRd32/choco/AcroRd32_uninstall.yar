rule AcroRd32_uninstall {
	meta:
		description = "Auto generation for AcroRd32"
		author = "David Cruciani"
		date = "2021-11-18"
		versionApp = "21.7.20099.454979"
		uuid = "6683d5ed-fa1e-4f62-9485-57168bc03cf9"
		uninstaller = "choco"
	strings: 
		$s0 = /D\:\\B\\T\\BuildResults\\bin\\Release\\AcroRd32Info\.pdb/
		$s1 = /acrord32\~/
		$s2 = /ACRORD32\.EXE/
		$s3 = /acrord32\.exe\|a2dc27f7ffc8bfc4/
		$s4 = /acrord32info\.exe\|6f8a3483d76a00b6/
		$s5 = /AcroRd32\.exe/
		$s6 = /AcroRd32Info\.exehbin/
		$s7 = /AcroRd32Info\.pdb/
		$s8 = /AcroRd32\.dll/
		$s9 = /AcroRd32Info\.exe/
		$s10 = /acrord32res\.dll/
	condition:
		 ext_var of ($s*)
}