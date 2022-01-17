rule chrome_uninstall {
	meta:
		description = "Auto generation for chrome"
		author = "David Cruciani"
		date = "2021-10-28"
		versionApp = "95.0.4638.54"
		uuid = "d3bba22f-7758-4156-a21b-eff273a042d0"
		uninstaller = "choco"
	strings: 
		$s0 = /chrome\~/
		$s1 = / chrome\!z/
		$s2 = /chrome\.exe/
		$s3 = /google chrome\~/
		$s4 = /chromer\~/
		$s5 = /CHROME\.EXE/
		$s6 = /CHROME\_INSTALLE/
		$s7 = /chrome\:\/\/welcome\//
		$s8 = /chrome\:\/\/welcome/
		$s9 = /\]https\:\/\/chrome\.google\.com\/webstore\?hl\=fr/
		$s10 = /chrome\.exe6E5D3A/
		$s11 = /\/pages\/chrome\?app\@/
		$s12 = /ICROSOFT\.COM\/V8\.0\/PAGES\/CHROME\?A/
		$s13 = /PAGES\/CHROME\?AP\/NMARKE/
		$s14 = /do\_not\_launch\_chrome/
		$s15 = /make\_chrome\_default/
		$s16 = /make\_chrome\_default\_for\_user/
		$s17 = /do\-not\-launch\-chrome/
		$s18 = /make\-chrome\-default/
		$s19 = /register\-chrome\-browser/
		$s20 = /register\-chrome\-browser\-suffix/
		$s21 = /register\-dev\-chrome/
		$s22 = /remove\-chrome\-registration/
		$s23 = /rename\-chrome\-exe/
		$s24 = /try\-chrome\-again/
		$s25 = /chrome\-beta/
		$s26 = /chrome\-dev/
		$s27 = /chrome\-sxs/
		$s28 = /chrome\.exe6E5D3Ap/
		$s29 = /CHROME\_AD/
		$s30 = /CHROME\_OS/
		$s31 = /CHROME\_OS\_DEMO\_MODE/
		$s32 = /CHROME\_BROWSER/
		$s33 = /chrome\_signed\_in\_user/
		$s34 = /chrome\_policies/
		$s35 = /chrome\_user\_profile\_reports/
		$s36 = /chrome\_user\_profile\_infos/
		$s37 = /CHROME\_ENTERPRISE/
		$s38 = /CHROME\_EDUCATION/
		$s39 = /CHROME\_TERMINAL/
		$s40 = /CHROME\_BROWSER\_TPM\_KEY/
		$s41 = /CHROME\_BROWSER\_OS\_KEY/
		$s42 = /chrome\_desktop\_report\_request/
		$s43 = /chrome\_os\_user\_report\_request/
		$s44 = /chrome\_desktop\_report\_response/
		$s45 = /chrome\_os\_user\_report\_response/
	condition:
		 ext_var of ($s*)
}