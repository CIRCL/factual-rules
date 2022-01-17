rule PuTTY_fls_uninstall {
	meta:
		description = "Auto generation for PuTTY"
		author = "David Cruciani"
		date = "2021-10-28"
		versionApp = "Release 0.75"
		uuid = "bbedc62b-7da9-4050-b6af-b65e8129ea44"
		uninstaller = "msiexec"
	strings: 
		$s0 = /PuTTY/
		$s1 = /PuTTY \(64\-bit\)/
		$s2 = /PuTTY Manual\.lnk/
		$s3 = /PuTTY Web Site\.lnk/
		$s4 = /PuTTY\.lnk/
		$s5 = /PuTTYgen\.lnk/
		$s6 = /SimonTatham\_PuTTY/
		$s7 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_pageant\_exe/
		$s8 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_psftp\_exe/
		$s9 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_puttygen\_exe/
		$s10 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_putty\_chm/
		$s11 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_PuTTY\_website\_url/
		$s12 = /PUTTY\.EXE\-7D8FB982\.pf/
	condition:
		 ext_var of ($s*)
}