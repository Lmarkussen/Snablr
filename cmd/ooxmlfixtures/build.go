package main

import (
	"snablr/internal/officefixture"
)

func fixtures() map[string][]byte {
	out := map[string][]byte{}

	// --- DOCX ---
	out["norwegian-docx-pair.docx"] = officefixture.DOCX(
		officefixture.Paragraph("Brukernavn: svc_backup"),
		officefixture.Paragraph("Domene: KUNDE"),
		officefixture.Paragraph("Passord: Norsk-Hemmelig-123!"),
	)
	out["norwegian-docx-standalone.docx"] = officefixture.DOCX(officefixture.Paragraph("Passord: Norsk-Hemmelig-456!"))
	out["norwegian-docx-runs.docx"] = officefixture.DOCX(
		officefixture.RunParagraph("Bruker", "navn", ": ", "svc_runs"),
		officefixture.RunParagraph("Pass", "ord", ": ", "Run-Hemmelig-123!"),
	)
	out["norwegian-docx-table.docx"] = officefixture.DOCX(officefixture.Table(
		[]string{"Brukernavn", "svc_table"},
		[]string{"Passord", "Table-Hemmelig-123!"},
	))
	out["norwegian-docx-label-value.docx"] = officefixture.DOCX(
		officefixture.Paragraph("Brukernavn"),
		officefixture.Paragraph("svc_para"),
		officefixture.Paragraph("Passord"),
		officefixture.Paragraph("Para-Hemmelig-123!"),
	)
	out["norwegian-docx-label-blocks.docx"] = officefixture.DOCX(
		officefixture.Paragraph("Brukernavn"),
		officefixture.Paragraph("svc_block"),
		officefixture.Paragraph(""),
		officefixture.Paragraph("Passord"),
		officefixture.Paragraph("Block-Hemmelig-123!"),
	)
	out["passordliste.docx"] = officefixture.DOCX(
		officefixture.Paragraph("Brukernavn: svc_word"),
		officefixture.Paragraph("Passord: Word-Hemmelig-999!"),
	)
	out["english-docx-pair.docx"] = officefixture.DOCX(
		officefixture.Paragraph("Username: svc_eng"),
		officefixture.Paragraph("Domain: KUNDE"),
		officefixture.Paragraph("Password: English-Hemmelig-123!"),
	)
	out["norwegian-docx-utf8.docx"] = officefixture.DOCX(
		officefixture.Paragraph("Brukernavn: backup-tjeneste"),
		officefixture.Paragraph("Domene: ØKONOMI"),
		officefixture.Paragraph("Passord: Påloggings-Hemmelighet-ÆØÅ-123!"),
	)
	out["norwegian-docx-policy.docx"] = officefixture.DOCX(officefixture.Paragraph("This document describes our PassordPolicy."))
	out["norwegian-docx-documentation.docx"] = officefixture.DOCX(
		officefixture.Paragraph("Passordrutiner"),
		officefixture.Paragraph("Passordkrav: Minimum 14 tegn"),
		officefixture.Paragraph("PassordLengde: 14"),
		officefixture.Paragraph("PassordKompleksitet: Aktivert"),
	)
	out["passordpolicy.docx"] = officefixture.DOCX(officefixture.Paragraph("Policy document, no credentials here."))

	// --- XLSX ---
	out["norwegian-xlsx-pair.xlsx"] = officefixture.XLSX([][]string{
		{"Brukernavn", "svc_excel"},
		{"Passord", "Excel-Hemmelig-123!"},
		{"Domene", "KUNDE"},
	})
	out["norwegian-xlsx-multi.xlsx"] = officefixture.XLSX([][]string{
		{"Brukernavn", "Passord", "Domene"},
		{"user1", "Secret1-Norsk!", "KUNDE"},
		{"user2", "Secret2-Norsk!", "KUNDE"},
	})
	out["english-xlsx-pair.xlsx"] = officefixture.XLSX([][]string{
		{"Username", "svc_eng"},
		{"Password", "English-Excel-123!"},
	})
	out["norwegian-xlsx-policy.xlsx"] = officefixture.XLSX([][]string{
		{"PassordLengde", "14"},
		{"PassordKompleksitet", "Aktivert"},
	})
	out["norwegian-xlsx-utf8.xlsx"] = officefixture.XLSX([][]string{
		{"Brukernavn", "tjeneste-bruker-Ø"},
		{"Passord", "Regnskap-ÆØÅ-123!"},
		{"Domene", "ØKONOMI"},
	})

	// --- PPTX ---
	out["norwegian-pptx-pair.pptx"] = officefixture.PPTX([]string{
		"Brukernavn: svc_ppt",
		"Passord: PowerPoint-Hemmelig-123!",
	})
	out["english-pptx-pair.pptx"] = officefixture.PPTX([]string{
		"Username: svc_ppt_eng",
		"Password: English-PowerPoint-123!",
	})
	out["norwegian-pptx-policy.pptx"] = officefixture.PPTX([]string{"Passordkrav: Minimum 14 tegn"})

	// --- Delimited exports ---
	out["norwegian-credentials.csv"] = []byte("Brukernavn,Passord,Domene\nsvc_csv,Csv-Hemmelig-123!,KUNDE\n")
	out["norwegian-credentials.tsv"] = []byte("Brukernavn\tPassord\tDomene\nsvc_tsv\tTsv-Hemmelig-123!\tKUNDE\n")
	out["norwegian-policy.csv"] = []byte("Setting,Value\nPassordPolicy,Strong\n")
	out["english-credentials.csv"] = []byte("Username,Password,Domain\nsvc_csv_eng,English-Csv-123!,KUNDE\n")

	// --- Filename discovery (content intentionally credential-free) ---
	out["gamle_passord.txt"] = []byte("Gammel oversikt.\n")
	out["brukerpassord.csv"] = []byte("Brukernavn,Passord\n")
	out["innlogging-info.txt"] = []byte("Innloggingsinformasjon.\n")
	out["palogging.txt"] = []byte("Palogging til tjenesten.\n")
	out["passordkrav.docx"] = officefixture.DOCX(officefixture.Paragraph("Passordkrav: Minimum 14 tegn"))
	out["passordrutiner.txt"] = []byte("Rutiner for passordhandtering.\n")
	out["veiledning-for-passord.docx"] = officefixture.DOCX(officefixture.Paragraph("Veiledning for passord."))
	out["passordliste.txt"] = []byte("Se vedlagt liste.\n")

	// --- Nested container ---
	out["nested-passordliste.zip"] = officefixture.ZIPBytes(map[string]string{
		"passordliste.docx": string(out["passordliste.docx"]),
	})

	return out
}
