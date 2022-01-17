rule firefox_exe {
	meta:
		description = "Auto generation for firefox"
		author = "David Cruciani"
		date = "2021-11-18"
		versionApp = "94.0"
		uuid = "26f31465-79f6-45b3-ad37-96f2c1d375ab"
		uninstaller = "choco"
	strings: 
		$h = {4300 6f00 6d00 7000 6100 6e00 7900 4e00 
6100 6d00 6500 0000 0000 4d00 6f00 7a00 
6900 6c00 6c00 6100 2000 4300 6f00 7200 
7000 6f00 7200 6100 7400 6900 6f00 6e00 
0000 3800 0800 0100 4600 6900 6c00 6500 
4400 6500 7300 6300 7200 6900 7000 7400 
6900 6f00 6e00 0000 0000 4600 6900 7200 
6500 6600 6f00 7800 0000                
}
	condition:
		$h
}