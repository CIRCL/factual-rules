rule PuTTY_install {
	meta:
		description = "Auto generation for PuTTY"
		author = "David Cruciani"
		date = "2021-10-28"
		versionApp = "Release 0.75"
		uuid = "aea0f963-8e31-4030-a20b-9afbcd3e5c40"
		uninstaller = "msiexec"
	strings: 
		$s0 = /putty\.exe\|a07396d107f47123/
		$s1 = /puttygen\.exe\|a8e024fc7459f5f3/
		$s2 = /PuTTY/
		$s3 = /putty\.exe/
		$s4 = /putty\~/
		$s5 = /puttygen\~/
		$s6 = /putty web site\~/
		$s7 = /putty manual\~/
		$s8 = /PuTTY\-UsfH/
		$s9 = /PuTTY\-UsH/
		$s10 = /putty\.exH/
		$s11 = /PuTTY\-User\-Key\-FUser\-Key\-File\-2/
		$s12 = /PuTTY Key File Warning/
		$s13 = /putty\-private\-key\-file\-mac\-key/
		$s14 = /PuTTY key format too new/
		$s15 = /Software\\SimonTatham\\PuTTY\\Sessions/
		$s16 = /\%s\\putty\_\%lu\_\%llu\.chm/
		$s17 = /\-restrict\_putty\_acl/
		$s18 = /\-restrict\-putty\-acl/
		$s19 = /Software\\SimonTatham\\PuTTY\\CHMPath/
		$s20 = /Software\\SimonTatham\\PuTTY64\\CHMPath/
		$s21 = /reencrypt\@putty\.projects\.tartarus\.org/
		$s22 = /reencrypt\-all\@putty\.projects\.tartarus\.org/
		$s23 = /add\-ppk\@putty\.projects\.tartarus\.org/
		$s24 = /list\-extended\@putty\.projects\.tartarus\.org/
		$s25 = /PuTTY\-User\-Key\-File\-/
		$s26 = /Unable to execute PuTTY\!/
		$s27 = /ofC\:\\Program Files\\PuTTY\\p/
		$s28 = /\|putty/
		$s29 = /\|putty manual/
		$s30 = /\|puttygen/
		$s31 = /\*\|putty/
		$s32 = /\*\|puttygen/
		$s33 = /PuTTY\_File/
		$s34 = /PuTTYgen\_File/
		$s35 = /PuTTY Installer/
		$s36 = /PuTTY release 0\.75 installer/
		$s37 = /PuTTY README/
		$s38 = /puttygen\.exe/
		$s39 = /putty\.chm/
		$s40 = /23\\PuTTY \(64\-bit\)\\3/
		$s41 = /C\:\\Program Files\\PuTTY\\/
		$s42 = /PuTTY\)/
		$s43 = /SimonTatham\.PuTTY3/
		$s44 = /C\:\\Program Files\\PuTTY\\3/
		$s45 = /PuTTYgen/
		$s46 = /mybzcwzb\|PuTTY Manual/
		$s47 = /lnzrzvod\|PuTTY Web Site/
		$s48 = /Edit with PuTTYgen\$/
		$s49 = /application\/x\-putty\-private\-key\$/
		$s50 = /PuTTY Private Key File\$/
		$s51 = /Software\\SimonTatham\\PuTTY64\\PPKAssociation/
		$s52 = /Software\\SimonTatham\\PuTTY64\\PathEntry/
		$s53 = /Software\\SimonTatham\\PuTTY64\\StartMenu/
		$s54 = /putty\.msi/
		$s55 = /PuTTY64/
		$s56 = /putty\.cab/
		$s57 = /\*\|PuTTYB\*\|/
		$s58 = /Eputty/
		$s59 = /O\*\|PuTTY/
		$s60 = /\(Gputty w/
		$s61 = /siteOPuTTY W/
		$s62 = /DSimonTatham\.PuTTY/
		$s63 = /PUTTY\.EXE/
		$s64 = / PUTTY\(\~1/
		$s65 = /  PUTTYM\~1\.LNK/
		$s66 = /  PUTTYW\~1\.LNK/
		$s67 = /  PuTTY\.lnk/
		$s68 = /  PuTTYgen\.lnk/
		$s69 = /\/faq\-putty\-org\.html/
		$s70 = /\/faq\-puttyputty\.html/
		$s71 = /\/faq\-sillyputty\.html/
		$s72 = /\/pubkey\-puttygen\.html/
		$s73 = /\/puttygen\-comment\.html/
		$s74 = /\/puttygen\-conversions\.html/
		$s75 = /\/puttygen\-fingerprint\.html/
		$s76 = /\/puttygen\-generate\.html/
		$s77 = /\/puttygen\-generating\.html/
		$s78 = /\/puttygen\-keytype\.html/
		$s79 = /\/puttygen\-load\.html/
		$s80 = /\/puttygen\-passphrase\.html/
		$s81 = /\/puttygen\-pastekey\.html/
		$s82 = /\/puttygen\-primes\.html/
		$s83 = /\/puttygen\-save\-params\.html/
		$s84 = /\\\&\/puttygen\-save\-passphrase\-hashing\.html/
		$s85 = /\/puttygen\-save\-ppk\-version\.html/
		$s86 = /\/puttygen\-savepriv\.html/
		$s87 = /\/puttygen\-savepub\.html/
		$s88 = /\/puttygen\-strength\.html/
		$s89 = /PuTTY User Manual/
		$s90 = /SSHCONNECTION\@putty\.projects\.tartarus\.org\-2\.0\-/
		$s91 = /Local\\putty\-connshare\-mutex/
		$s92 = /Software\\SimonTatham\\PuTTY\\SshHostKeys/
		$s93 = /winadj\@putty\.projects\.tartarus\.org/
		$s94 = /simple\@putty\.projects\.tartarus\.org/
		$s95 = /putty\.log/
		$s96 = /\\\\\.\\pipe\\putty\-connshare/
		$s97 = /Software\\SimonTatham\\PuTTY/
		$s98 = /\\PUTTY\.RND/
		$s99 = /SSHCONNECTION\@putty\.projects\.tartarus\.org\-/
		$s100 = /PuTTY Secure Copy client/
		$s101 = /PuTTYConfigBox/
		$s102 = /putty \%s\&\%p\:\%u/
		$s103 = /PuTTY remote printer output/
		$s104 = /Software\\SimonTatham\\PuTTY\\Jumplist/
		$s105 = /putty\%s\%s/
		$s106 = /putty \%s\@\%s/
		$s107 = /Connect to PuTTY session \'/
		$s108 = /PuTTYgen\.exe/
		$s109 = /   name\=\"PuTTY\"/
		$s110 = /puttygen\-pastekey/
		$s111 = /puttygen\-savepriv/
		$s112 = /puttygen\-fingerprint/
		$s113 = /puttygen\-comment/
		$s114 = /puttygen\-conversions/
		$s115 = /PuTTYgen Error/
		$s116 = /PuTTYgen Fatal Error/
		$s117 = /puttygen\-save\-ppk\-version/
		$s118 = /pubkey\-puttygen/
		$s119 = /puttygen\-strength/
		$s120 = /PuTTYgen Warning/
		$s121 = /puttygen\-save\-passphrase\-hashing/
		$s122 = /puttygen\-generate/
		$s123 = /puttygen\-passphrase/
		$s124 = /puttygen\-keytype/
		$s125 = /PuTTYgen Notice/
		$s126 = /puttygen\-load/
		$s127 = /puttygen\-savepub/
		$s128 = /PuTTY\-User\-Key\-File\-\%u\: \%s/
		$s129 = /   name\=\"PuTTYgen\"/
	condition:
		 ext_var of ($s*)
}