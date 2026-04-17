rule POLYGLOT_IMAGEandZIP {
	meta:
		author = "WhosWho"
		description = "Image and ZIP Polyglot file detection"
	strings:
		$png = { 89 50 4E 47 0D 0A 1A 0A }

		$jpg1 = { FF D8 FF DB }
		$jpg2 = { FF D8 FF E0 00 10 4A 46 49 46 00 01 }
		$jpg3 = { FF D8 FF EE }
		$jpg4 = { FF D8 FF E1 ?? ?? 45 78 69 66 00 00 }
		$jpg5 = { FF D8 FF E0 }

		$zip = { 50 4B 03 04 }
	condition:
		($png at 0 or $jpg1 at 0  or $jpg2 at 0 or $jpg3 at 0 or $jpg4 at 0 or $jpg5 at 0) and $zip
}

rule POLYGLOT_IMAGEandPDF {
	meta:
		author = "WhosWho"
		description = "Image and PDF Polyglot file detection"
	strings:
		$png = { 89 50 4E 47 0D 0A 1A 0A }

		$jpg1 = { FF D8 FF DB }
		$jpg2 = { FF D8 FF E0 00 10 4A 46 49 46 00 01 }
		$jpg3 = { FF D8 FF EE }
		$jpg4 = { FF D8 FF E1 ?? ?? 45 78 69 66 00 00 }
		$jpg5 = { FF D8 FF E0 }

		$pdf = { 25 50 44 46 2D }
	condition:
		($png at 0 or $jpg1 at 0  or $jpg2 at 0 or $jpg3 at 0 or $jpg4 at 0 or $jpg5 at 0) and $pdf
}

rule POLYGLOT_PDFandZIP {
	meta:
		author = "WhosWho"
		description = "PDF and ZIP Polyglot file detection"
	strings:
		$pdf = { 25 50 44 46 2D }

		$zip = { 50 4B 03 04 }
	condition:
		$pdf and $zip
}

rule POLYGLOT_PDFandVIDEO {
	meta:
		author = "WhosWho"
		description = "PDF and Video Polyglot file detection"
	strings:
		$pdf = { 25 50 44 46 2D }

		$mp4_A = { 66 74 79 70 69 73 6F 6D }
		$mp4_B = { 66 74 79 70 4D 53 4E 56 }
	condition:
		$pdf and ($mp4_A or $mp4_B)
}

rule POLYGLOT_ZIPandVIDEO {
		meta:
		author = "WhosWho"
		description = "ZIP and Video Polyglot file detection"
	strings:
		$zip = { 50 4B 03 04 }

		$mp4_A = { 66 74 79 70 69 73 6F 6D }
		$mp4_B = { 66 74 79 70 4D 53 4E 56 }
	condition:
		$zip and ($mp4_A or $mp4_B)
}

rule POLYGLOT_IMAGEandVIDEO {
	meta:
		author = "WhosWho"
		description = "Image and Video Polyglot file detection"
	strings:
		$png = { 89 50 4E 47 0D 0A 1A 0A }

		$jpg1 = { FF D8 FF DB }
		$jpg2 = { FF D8 FF E0 00 10 4A 46 49 46 00 01 }
		$jpg3 = { FF D8 FF EE }
		$jpg4 = { FF D8 FF E1 ?? ?? 45 78 69 66 00 00 }
		$jpg5 = { FF D8 FF E0 }

		$mp4_A = { 66 74 79 70 69 73 6F 6D }
		$mp4_B = { 66 74 79 70 4D 53 4E 56 }
	condition:
		($png or $jpg1 or $jpg2 or $jpg3 or $jpg4 or $jpg5) and ($mp4_A or $mp4_B)
}