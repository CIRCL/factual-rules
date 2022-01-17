rule chrome_exe {
	meta:
		description = "Auto generation for chrome"
		author = "David Cruciani"
		date = "2021-10-28"
		versionApp = "95.0.4638.54"
		uuid = "6b87f487-eb39-464e-a2be-07e784c41db9"
		uninstaller = "choco"
	strings: 
		$h = {4300 6f00 6d00 7000 6100 6e00 7900 4e00 
6100 6d00 6500 0000 0000 4700 6f00 6f00 
6700 6c00 6500 2000 4c00 4c00 4300 0000 
0000 4400 0e00 0100 4600 6900 6c00 6500 
4400 6500 7300 6300 7200 6900 7000 7400 
6900 6f00 6e00 0000 0000 4700 6f00 6f00 
6700 6c00 6500 2000 4300 6800 7200 6f00 
6d00 6500 0000                          
}
	condition:
		$h
}