rule WinRAR_fls_uninstall {
	meta:
		description = "Auto generation for WinRAR"
		author = "David Cruciani"
		date = "2022-01-13"
		versionApp = "6.2.0"
		uuid = "7d585171-6ecb-4f4b-8017-f95f260a5005"
		uninstaller = "choco"
	strings: 
		$s0 = /WinRAR/
		$s1 = /winrar\.chm/
		$s2 = /WinRAR\.exe/
		$s3 = /winrar\.lng/
		$s4 = /winrar\.6\.02/
		$s5 = /winrar/
		$s6 = /winrar\.nupkg/
		$s7 = /winrar\.nuspec/
		$s8 = /WinRAR\.lnk/
		$s9 = /Aide de WinRAR\.lnk/
		$s10 = /logo\-winrar\[1\]\.gif/
		$s11 = /winrar\_books\[1\]\.png/
		$s12 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_WinRAR\_Rar\_txt/
		$s13 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_WinRAR\_WhatsNew\_txt/
		$s14 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_WinRAR\_winrar\_chm/
		$s15 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_WinRAR\_WinRAR\_exe/
		$s16 = /WINRAR\-X64\-602FR\.EXE\-42BB53C8\.pf/
		$s17 = /WINRAR\.EXE\-94E7D80C\.pf/
	condition:
		 ext_var of ($s*)
}