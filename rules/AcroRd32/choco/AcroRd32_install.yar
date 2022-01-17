rule AcroRd32_install {
	meta:
		description = "Auto generation for AcroRd32"
		author = "David Cruciani"
		date = "2021-11-18"
		versionApp = "21.7.20099.454979"
		uuid = "79d9357e-fee4-43d7-a3dd-f987ebba15d6"
		uninstaller = "choco"
	strings: 
		$s0 = /D\:\\B\\T\\BuildResults\\bin\\Release\\AcroRd32Info\.pdb/
		$s1 = /acrord32\~/
		$s2 = /acrord32\.exe\|a2dc27f7ffc8bfc4/
		$s3 = /acrord32info\.exe\|6f8a3483d76a00b6/
		$s4 = /AcroRd32/
		$s5 = /AcroRd32\.exe/
		$s6 = /AcroRd32Info\.exehbin/
		$s7 = /AcroRd32Exe\.pdb/
		$s8 = /AcroRd32IsBrokerProcess/
		$s9 = /AcroRd32\.pdb/
		$s10 = /AcroRd32\.dll/
		$s11 = /\|rdr\|\\acrord32\.dll/
		$s12 = /\|rdr\|\\acrord32\.exe/
		$s13 = /\|rdr\|\\AcroRd32Res\.dll/
		$s14 = /\|tmp\|\\acrord32\_sbx/
		$s15 = /\\AcroRd32\.exe/
		$s16 = /\|rdr\|\\AcroRd32\.dll/
		$s17 = /D\:\\B\\T\\BuildResults\\bin\\Release\\AcroRd32Exe\.pdb/
		$s18 = /AcroRd32Info\.pdb/
		$s19 = /ACRORD32\.EXE/
		$s20 = /D\:\\B\\T\\BuildResults\\bin\\Release\\AcroRd32\.pdb/
		$s21 = /AcroRd32Info\.exe/
		$s22 = /acrord32res\.dll/
	condition:
		 ext_var of ($s*)
}