rule PuTTY_uninstall {
	meta:
		description = "Auto generation for PuTTY"
		author = "David Cruciani"
		date = "2021-10-28"
		versionApp = "Release 0.75"
		uuid = "5d184234-3d82-4de4-b56d-863cb835d9dd"
		uninstaller = "msiexec"
	strings: 
		$s0 = /putty\.exe\|a07396d107f47123/
		$s1 = /puttygen\.exe\|a8e024fc7459f5f3/
		$s2 = /putty\~/
		$s3 = /puttygen\~/
		$s4 = /putty web site\~/
		$s5 = /putty manual\~/
		$s6 = /\*\|PuTTYB\*\|/
		$s7 = /Eputty/
		$s8 = /O\*\|PuTTY/
		$s9 = /\(Gputty w/
		$s10 = /siteOPuTTY W/
		$s11 = /DSimonTatham\.PuTTY/
		$s12 = /PUTTY\.EXE/
		$s13 = /ofC\:\\Program Files\\PuTTY\\p/
		$s14 = /\|putty/
		$s15 = /\|putty manual/
		$s16 = /\|puttygen/
		$s17 = /\*\|putty/
		$s18 = /\*\|puttygen/
		$s19 = /PuTTY/
		$s20 = /puttygen\.exe/
		$s21 = /putty\.chm/
		$s22 = /23\\PuTTY \(64\-bit\)\\3/
		$s23 = /C\:\\Program Files\\PuTTY\\/
		$s24 = /PuTTY\)/
		$s25 = /SimonTatham\.PuTTY3/
		$s26 = /C\:\\Program Files\\PuTTY\\3/
		$s27 = /PuTTYgen/
		$s28 = /mybzcwzb\|PuTTY Manual/
		$s29 = /lnzrzvod\|PuTTY Web Site/
		$s30 = /Edit with PuTTYgen\$/
		$s31 = /application\/x\-putty\-private\-key\$/
		$s32 = /PuTTY Private Key File\$/
		$s33 = /Software\\SimonTatham\\PuTTY64\\CHMPath/
		$s34 = /Software\\SimonTatham\\PuTTY64\\PPKAssociation/
		$s35 = /Software\\SimonTatham\\PuTTY64\\PathEntry/
		$s36 = /Software\\SimonTatham\\PuTTY64\\StartMenu/
		$s37 = /putty\.msi/
		$s38 = /putty\.cab/
		$s39 = /ofC\:\\Program Files\\PuTTY\\p\`/
		$s40 = /PuTTY64/
	condition:
		 ext_var of ($s*)
}