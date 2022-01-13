rule PuTTY_fls_install {
	meta:
		description = "Auto generation for PuTTY"
		author = "David Cruciani"
		date = "2021-10-28"
		versionApp = "Release 0.75"
		uuid = "cf9a2a69-67fd-4625-a2c9-719e93d5efab"
		uninstaller = "msiexec"
	strings: 
		$s0 = /PuTTY/
		$s1 = /putty\.chm/
		$s2 = /putty\.exe/
		$s3 = /puttygen\.exe/
		$s4 = /PuTTY \(64\-bit\)/
		$s5 = /PuTTY Manual\.lnk/
		$s6 = /PuTTY Web Site\.lnk/
		$s7 = /PuTTY\.lnk/
		$s8 = /PuTTYgen\.lnk/
		$s9 = /SimonTatham\_PuTTY/
		$s10 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_pageant\_exe/
		$s11 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_psftp\_exe/
		$s12 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_puttygen\_exe/
		$s13 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_putty\_chm/
		$s14 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_website\_url/
		$s15 = /PUTTY\.EXE\-7D8FB982\.pf/
	condition:
		 ext_var of ($s*)
}