rule WinRAR_install {
	meta:
		description = "Auto generation for WinRAR"
		author = "David Cruciani"
		date = "2022-01-13"
		versionApp = "6.2.0"
		uuid = "e09787eb-da08-4f86-a4c4-281cb90e70bb"
		uninstaller = "choco"
	strings: 
		$s0 = /  name\=\"WinRAR\"/
		$s1 = /  name\=\"WinRAR SFX\"/
		$s2 = / winrar/
		$s3 = /winrar/
		$s4 = / winrarOAide de/
		$s5 = / WinRARB\*\|/
		$s6 = /O\|winrar/
		$s7 = /\|WinRARB\*\|/
		$s8 = /winrar\.exe\|55dc552369664f2a/
		$s9 = /WinRAR\.chm/
		$s10 = /WinRAR\.exe/
		$s11 = /winrar\.lng/
		$s12 = /winrar\.chw/
		$s13 = /WinRAR/
		$s14 = /R\(J  WinRAR\.exe/
		$s15 = /Rv9  winrar\.chm/
		$s16 = /winrar\.chm/
		$s17 = /winrar\~/
		$s18 = /de winrar\~/
		$s19 = /aide de winrar\~/
		$s20 = / WinRAR \!\<\/h5\>/
		$s21 = /es accidentelles par WinRAR\./
		$s22 = /tre facultatif\, WinRAR d/
		$s23 = /ant WinRAR /
		$s24 = /faut WinRAR cr/
		$s25 = /ches\. WinRAR/
		$s26 = /\, WinRAR essayera de d/
		$s27 = /rs par WinRAR sont /
		$s28 = /le\. Si WinRAR d/
		$s29 = /faut\, WinRAR r/
		$s30 = / WinRAR /
		$s31 = /es \"Archive WinRAR\" et /
		$s32 = /ration WinRAR et les bo/
		$s33 = /tre de WinRAR comme dans/
		$s34 = /grer WinRAR /
		$s35 = /es\, WinRAR/
		$s36 = /tat de WinRAR\./
		$s37 = /demment\, WinRAR n\'/
		$s38 = / des utilisateurs de WinRAR\./
		$s39 = /e\, WinRAR affichait un num/
		$s40 = /tres de WinRAR incluait/
		$s41 = /nes WinRAR pr/
		$s42 = /me d\'interface WinRAR /
		$s43 = / WinRAR\.exe et est ignor/
		$s44 = /tres WinRAR et s/
		$s45 = /dentes de WinRAR\. Les donn/
		$s46 = /taient illisibles\. WinRAR /
		$s47 = /tres de WinRAR\,/
		$s48 = / de WinRAR/
		$s49 = /es\, WinRAR v/
		$s50 = /es dans Unix\, WinRAR associe/
		$s51 = /  15\. WinRAR emp/
		$s52 = /s\, WinRAR tente de d/
		$s53 = /tres de WinRAR\. Vous pr/
		$s54 = / Fichier WinRAR\.ini /
		$s55 = / de l\'aide WinRAR\./
		$s56 = /te de dialogue WinRAR /
		$s57 = / de WinRAR gr/
		$s58 = /dentes de WinRAR\./
		$s59 = /mentaire ZIP\. WinRAR peut d/
		$s60 = /s par WinRAR comme /
		$s61 = / par WinRAR\./
		$s62 = /faut\, WinRAR continuait /
		$s63 = /tres de WinRAR\./
		$s64 = / contextuel de WinRAR \;/
		$s65 = /compression\. WinRAR cr/
		$s66 = /dentes de WinRAR\,/
		$s67 = /diteur externe\, WinRAR /
		$s68 = /dentes de WinRAR /
		$s69 = /e\, WinRAR /
		$s70 = / d\'installer WinRAR version/
		$s71 = /tre principale de WinRAR/
		$s72 = /s\:IDS\_WINRARHELP/
		$s73 = /s\:IDS\_WINRARARC/
		$s74 = /s\:IDS\_WINRARZIPARC/
		$s75 = /s\:IDS\_WINRARDESC/
		$s76 = /CMT\; WinRAR/
		$s77 = /Title\=WinRAR 6\.02/
		$s78 = /Path\=WinRAR/
		$s79 = /Delete\=WinRAR\.hlp/
		$s80 = /WinRAR4\-/
		$s81 = /WinRARc/
		$s82 = /WinRARr/
		$s83 = /WinRAR32/
		$s84 = /WinRAR\.ZIPl/
		$s85 = /WinRARe/
		$s86 = /WinRAR\.REV/
		$s87 = /WinRAR archiver/
		$s88 = /\.C\%\%Program Files\%WinRAR/
		$s89 = /winrar v6\.02 \[Approved\]/
		$s90 = /winrar\.nuspec /
		$s91 = /\#\# WinRAR/
		$s92 = /winrar\.nuspecPK/
		$s93 = /\$packageSearch \= \"WinRAR\*\"/
		$s94 = /WinRAR SFX/
		$s95 = /    \<id\>winrar\<\/id\>/
		$s96 = /    \<title\>WinRAR\<\/title\>/
		$s97 = /\/html\/HELPWinRARIni\.htm/
		$s98 = /\/winrar\.hhc/
		$s99 = /\/winrar\.hhk/
		$s100 = /WinRAR\.lnk/
		$s101 = / WinRAR/
		$s102 = /v  WinRAR\.lnk/
		$s103 = /s\:IDS\_NEWERWINRAR/
		$s104 = /u rapide de WinRAR/
		$s105 = /WINRAR\.EXE/
		$s106 = /WINRAR\-X64\-602F/
	condition:
		 ext_var of ($s*)
}