rule WinRAR_uninstall {
	meta:
		description = "Auto generation for WinRAR"
		author = "David Cruciani"
		date = "2022-01-13"
		versionApp = "6.2.0"
		uuid = "734adcbe-cbe7-4224-9ffd-c24f693982b8"
		uninstaller = "choco"
	strings: 
		$s0 = /winrar\.exe\|55dc552369664f2a/
		$s1 = /winrar\~/
		$s2 = /de winrar\~/
		$s3 = /aide de winrar\~/
		$s4 = / winrar/
		$s5 = /winrar/
		$s6 = / winrarOAide de/
		$s7 = / WinRARB\*\|/
		$s8 = /O\|winrar/
		$s9 = /\|WinRARB\*\|/
		$s10 = /WinRAR\.chm/
		$s11 = /WinRAR\.exe/
		$s12 = /winrar\.lng/
		$s13 = /winrar\.chw/
		$s14 = /WINRAR\.EXE/
		$s15 = /WINRAR\-X64\-602F/
		$s16 = /winrar v6\.02/
		$s17 = /\$packageSearch \= \"WinRAR\*\"/
		$s18 = / WinRAR \!\<\/h5\>/
		$s19 = /\.C\%\%Program Files\%WinRAR/
		$s20 = /WinRAR SFX/
		$s21 = /WinRAR/
		$s22 = /WinRARe/
		$s23 = /WinRAR\.REV/
		$s24 = /WinRAR archiver/
		$s25 = /WinRAR4\-X/
		$s26 = /WinRARc/
		$s27 = /WinRARr/
		$s28 = /WinRAR32/
		$s29 = /WinRAR32X/
		$s30 = /WinRAR\.ZIPl/
		$s31 = /winrar v6\.02 \[Approved\]/
		$s32 = /winrar\.nuspec /
		$s33 = /\#\# WinRAR/
		$s34 = /winrar\.nuspecPK/
		$s35 = /    \<id\>winrar\<\/id\>/
		$s36 = /    \<title\>WinRAR\<\/title\>/
		$s37 = /u rapide de WinRAR/
	condition:
		 ext_var of ($s*)
}