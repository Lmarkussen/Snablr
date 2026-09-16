package main

import (
	"strings"

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

	// --- Live-shape filename family: "PasswordList" ---
	// A leading number, a space, and capitalisation must not defeat discovery,
	// and the credential may live in any rendered part of the document.
	out["passordliste-eksempel.docx"] = officefixture.DOCX(
		officefixture.Paragraph("PasswordList"),
		officefixture.Paragraph("Brukernavn: svc_test"),
		officefixture.Paragraph("Domene: KUNDE"),
		officefixture.Paragraph("Passord: Test-Hemmelig-123!"),
	)
	out["PasswordList-footnote.docx"] = officefixture.DOCXWithParts(map[string]string{
		"word/footnotes.xml": wordNotePart("footnotes", "footnote",
			officefixture.Paragraph("Brukernavn: svc_foot"),
			officefixture.Paragraph("Passord: Fotnote-Hemmelig-123!")),
	}, officefixture.Paragraph("PasswordList"))
	out["PasswordList-comment.docx"] = officefixture.DOCXWithParts(map[string]string{
		"word/comments.xml": wordNotePart("comments", "comment",
			officefixture.Paragraph("Brukernavn: svc_kommentar"),
			officefixture.Paragraph("Passord: Kommentar-Hemmelig-123!")),
	}, officefixture.Paragraph("PasswordList"))
	out["PasswordList-smartart.docx"] = officefixture.DOCXWithParts(map[string]string{
		"word/diagrams/data1.xml": drawingMLPart(
			"Brukernavn: svc_smart",
			"Passord: SmartArt-Hemmelig-123!",
		),
	}, officefixture.Paragraph("PasswordList"))
	out["passordliste-eksempel.xlsx"] = officefixture.XLSX([][]string{
		{"Brukernavn", "Passord"},
		{"svc_excel", "Excel-Hemmelig-123!"},
	})
	out["PasswordList-comment.xlsx"] = officefixture.XLSXWithParts(map[string]string{
		"xl/comments1.xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<comments xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">` +
			`<authors><author>Drift</author></authors><commentList><comment ref="B2" authorId="0"><text>` +
			`<r><t>Brukernavn: svc_excel_kommentar</t></r>` +
			`<r><t xml:space="preserve">&#10;Passord: ExcelKommentar-Hemmelig-123!</t></r>` +
			`</text></comment></commentList></comments>`,
	}, [][]string{{"Felt", "Verdi"}, {"Konto", "Se kommentar"}}, false)
	out["PasswordList-drawing.xlsx"] = officefixture.XLSXWithParts(map[string]string{
		"xl/drawings/drawing1.xml": drawingMLPart(
			"Brukernavn: svc_tegning",
			"Passord: Tegning-Hemmelig-123!",
		),
	}, [][]string{{"Felt", "Verdi"}, {"Konto", "Se tekstboks"}}, false)
	out["PasswordList.txt"] = []byte("Brukernavn: svc_txt\r\nPassord: Txt-Hemmelig-123!\r\n")
	// A credential-only note replicated in the folder-name vocabulary.
	out["PasswordLists/PasswordList.txt"] = []byte("Brukernavn: svc_mappe\r\nPassord: Mappe-Hemmelig-123!\r\n")

	// --- Header-row credential tables (row 1 defines columns, rows 2..N are
	// independent credential records). ---
	out["table-a-mixed.docx"] = officefixture.DOCX(tableCells(
		[]string{"USERNAME", "Passord"},
		[]string{"Bob", "Synthetic-Bob-123!"},
		[]string{"Jane", "Synthetic-Jane-456!"},
	))
	out["table-b-norwegian.docx"] = officefixture.DOCX(tableCells(
		[]string{"Brukernavn", "Passord"},
		[]string{"ola", "Norsk-Ola-123!"},
		[]string{"kari", "Norsk-Kari-456!"},
	))
	out["table-c-english.docx"] = officefixture.DOCX(tableCells(
		[]string{"Username", "Password"},
		[]string{"alice", "English-Alice-123!"},
		[]string{"bob", "English-Bob-456!"},
	))
	out["table-d-domain.docx"] = officefixture.DOCX(tableCells(
		[]string{"Domene", "Brukernavn", "Passord"},
		[]string{"KUNDE", "svc_backup", "Backup-123!"},
		[]string{"KUNDE", "svc_sql", "SQL-456!"},
	))
	out["table-e-reversed.docx"] = officefixture.DOCX(tableCells(
		[]string{"Passord", "Brukernavn"},
		[]string{"First-123!", "bruker1"},
		[]string{"Second-456!", "bruker2"},
	))
	out["table-f-extra-columns.docx"] = officefixture.DOCX(tableCells(
		[]string{"Server", "Brukernavn", "Passord", "Kommentar"},
		[]string{"SRV01", "svc_one", "One-123!", "gammel konto"},
		[]string{"SRV02", "svc_two", "Two-456!", "produksjon"},
	))
	out["table-g-blank-password.docx"] = officefixture.DOCX(tableCells(
		[]string{"Brukernavn", "Passord"},
		[]string{"user1", "One-123!"},
		[]string{"user2", ""},
		[]string{"user3", "Three-789!"},
	))
	out["table-h-blank-username.docx"] = officefixture.DOCX(tableCells(
		[]string{"Brukernavn", "Passord"},
		[]string{"", "Orphan-123!"},
		[]string{"user2", "Two-456!"},
	))
	out["table-i-split-runs.docx"] = officefixture.DOCX(officefixture.TableXML(
		[]officefixture.TableCell{officefixture.SplitCell("Bruker", "navn"), officefixture.SplitCell("Pass", "ord")},
		[]officefixture.TableCell{officefixture.SplitCell("svc", "_run"), officefixture.SplitCell("Run-", "123!")},
	))
	out["table-i2-multi-paragraph-header.docx"] = officefixture.DOCX(officefixture.TableXML(
		[]officefixture.TableCell{officefixture.ParaCell("USER", "NAME"), officefixture.ParaCell("Passord")},
		[]officefixture.TableCell{officefixture.Cell("svc_multi"), officefixture.Cell("Multi-123!")},
	))
	out["table-j-multiple-tables.docx"] = officefixture.DOCX(
		tableCells([]string{"Utstyr", "Antall"}, []string{"PC", "12"}),
		tableCells([]string{"Brukernavn", "Passord"}, []string{"svc1", "Secret1!"}),
		tableCells([]string{"Policy", "Krav"}, []string{"PassordLengde", "14"}),
	)
	out["table-p7-title-then-header.docx"] = officefixture.DOCX(
		officefixture.Paragraph("Kontooversikt"),
		officefixture.Paragraph(""),
		tableCells([]string{"Brukernavn", "Passord"}, []string{"svc1", "Secret1!"}),
	)
	out["table-p8-repeated-header.docx"] = officefixture.DOCX(tableCells(
		[]string{"Brukernavn", "Passord"},
		[]string{"user1", "One-123!"},
		[]string{"user2", "Two-456!"},
		[]string{"Brukernavn", "Passord"},
		[]string{"user3", "Three-789!"},
	))
	out["table-p9-merged-title.docx"] = officefixture.DOCX(officefixture.TableXML(
		[]officefixture.TableCell{officefixture.MergedCell(2, "Password List")},
		[]officefixture.TableCell{officefixture.Cell("Brukernavn"), officefixture.Cell("Passord")},
		[]officefixture.TableCell{officefixture.Cell("user1"), officefixture.Cell("One-123!")},
	))
	// Negative tables: documentation or policy material, never credentials.
	out["table-n1-policy.docx"] = officefixture.DOCX(tableCells(
		[]string{"Setting", "Value"},
		[]string{"PassordLengde", "14"},
		[]string{"PassordHistorikk", "24"},
	))
	out["table-n2-description.docx"] = officefixture.DOCX(tableCells(
		[]string{"Tema", "Beskrivelse"},
		[]string{"Passord", "Bruk sterke passord"},
	))
	out["table-n3-requirement.docx"] = officefixture.DOCX(tableCells(
		[]string{"Policy", "Requirement"},
		[]string{"Password", "Minimum 14 characters"},
	))
	out["table-n4-username-description.docx"] = officefixture.DOCX(tableCells(
		[]string{"Username", "Description"},
		[]string{"Bob", "Password reset owner"},
	))
	out["table-n5-password-comment.docx"] = officefixture.DOCX(tableCells(
		[]string{"Passord", "Kommentar"},
		[]string{"policy", "dokumentasjon"},
	))
	// Live-shape filename carrying a header-row credential table.
	out["PasswordList-table.docx"] = officefixture.DOCX(tableCells(
		[]string{"USERNAME", "Passord"},
		[]string{"Bob", "Synthetic-Bob-123!"},
		[]string{"Jane", "Synthetic-Jane-456!"},
	))
	out["nested-password-list.zip"] = officefixture.ZIPBytes(map[string]string{
		"PasswordList-table.docx": string(out["PasswordList-table.docx"]),
	})
	// Delimited and spreadsheet parity for the same logical table.
	out["table-credentials.csv"] = []byte("USERNAME,Passord\nBob,Synthetic-Bob-123!\nJane,Synthetic-Jane-456!\n")
	out["table-credentials.tsv"] = []byte("USERNAME\tPassord\nBob\tSynthetic-Bob-123!\nJane\tSynthetic-Jane-456!\n")
	out["table-credentials.xlsx"] = officefixture.XLSX([][]string{
		{"USERNAME", "Passord"},
		{"Bob", "Synthetic-Bob-123!"},
		{"Jane", "Synthetic-Jane-456!"},
	})

	return out
}

// tableCells builds a Word table from plain cell text.
func tableCells(rows ...[]string) string {
	tableRows := make([][]officefixture.TableCell, 0, len(rows))
	for _, row := range rows {
		cells := make([]officefixture.TableCell, 0, len(row))
		for _, cell := range row {
			cells = append(cells, officefixture.Cell(cell))
		}
		tableRows = append(tableRows, cells)
	}
	return officefixture.TableXML(tableRows...)
}

// wordNotePart builds a Word footnotes/comments/endnotes part holding one note.
func wordNotePart(part, element string, body ...string) string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:` + part + ` ` + officefixture.WNS + `>` +
		`<w:` + element + ` w:id="1">` + strings.Join(body, "") + `</w:` + element + `></w:` + part + `>`
}

// drawingMLPart builds a DrawingML part (SmartArt data or a shape text box).
func drawingMLPart(lines ...string) string {
	var builder strings.Builder
	builder.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><dgm:dataModel ` + officefixture.ANS + `><dgm:ptLst><dgm:pt><dgm:t>`)
	for _, line := range lines {
		builder.WriteString(`<a:p><a:r><a:t>` + line + `</a:t></a:r></a:p>`)
	}
	builder.WriteString(`</dgm:t></dgm:pt></dgm:ptLst></dgm:dataModel>`)
	return builder.String()
}
