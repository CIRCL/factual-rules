rule WinRAR_fls_install {
	meta:
		description = "Auto generation for WinRAR"
		author = "David Cruciani"
		date = "2022-01-13"
		versionApp = "6.2.0"
		uuid = "3f85f4af-0074-4613-9d8c-29cb72d98b6d"
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
		$s8 = /Aide de WinRAR\.lnk/
		$s9 = /WinRAR\.lnk/
		$s10 = /logo\-winrar\[1\]\.gif/
		$s11 = /winrar\_books\[1\]\.png/
		$s12 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_WinRAR\_Rar\_txt/
		$s13 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_WinRAR\_WhatsNew\_txt/
		$s14 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_WinRAR\_winrar\_chm/
		$s15 = /\{6D809377\-6AF0\-444B\-8957\-A3773F02200E\}\_WinRAR\_WinRAR\_exe/
		$s16 = /winrar\-x64\-602fr\.exe/
		$s17 = /WINRAR\-X64\-602FR\.EXE\-42BB53C8\.pf/
		$s18 = /WINRAR\.EXE\-94E7D80C\.pf/
	condition:
		 ext_var of ($s*)
}