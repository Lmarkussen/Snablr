package seed

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

type wimMemberTemplate struct {
	Path         string
	Content      []byte
	ContentStyle string
}

func wimMembersForVariant(ctx renderContext, variant templateVariant) []wimMemberTemplate {
	switch variant.ContentStyle {
	case "wim-ntds-system":
		return []wimMemberTemplate{
			{Path: "Windows/NTDS/ntds.dit", ContentStyle: "secret-store-marker"},
			{Path: "Windows/System32/config/SYSTEM", ContentStyle: "secret-store-marker"},
		}
	case "wim-hives":
		return []wimMemberTemplate{
			{Path: "Windows/System32/config/SAM", ContentStyle: "secret-store-marker"},
			{Path: "Windows/System32/config/SYSTEM", ContentStyle: "secret-store-marker"},
			{Path: "Windows/System32/config/SECURITY", ContentStyle: "secret-store-marker"},
		}
	case "wim-unattend":
		return []wimMemberTemplate{
			{Path: "Windows/Panther/unattend.xml", Content: wimUnattendXML(ctx)},
		}
	case "wim-mdt":
		return []wimMemberTemplate{
			{Path: "Deploy/Control/bootstrap.ini", Content: wimBootstrapINI(ctx)},
			{Path: "Deploy/Control/customsettings.ini", Content: wimCustomSettingsINI(ctx)},
			{Path: "Deploy/Control/tasksequence.xml", Content: wimTaskSequenceXML(ctx)},
		}
	default:
		return []wimMemberTemplate{
			{Path: "Windows/Temp/readme.txt", ContentStyle: "readme-noise"},
		}
	}
}

func buildWIMBytes(ctx renderContext, members []wimMemberTemplate) []byte {
	if _, err := exec.LookPath("wimlib-imagex"); err != nil {
		panic("wimlib-imagex is required to generate WIM seed fixtures")
	}

	tmpDir, err := os.MkdirTemp("", "snablr-seed-wim-tree-*")
	if err != nil {
		panic(fmt.Sprintf("build wim: temp dir: %v", err))
	}
	defer os.RemoveAll(tmpDir)

	for _, member := range members {
		memberPath := filepath.Join(tmpDir, filepath.FromSlash(strings.TrimPrefix(member.Path, "/")))
		if err := os.MkdirAll(filepath.Dir(memberPath), 0o755); err != nil {
			panic(fmt.Sprintf("build wim: mkdir %s: %v", member.Path, err))
		}
		content := member.Content
		if content == nil {
			memberCtx := ctx
			memberCtx.Filename = path.Base(member.Path)
			memberCtx.Format = inferFormat(memberCtx.Filename)
			memberCtx.ContentStyle = member.ContentStyle
			content = renderVariant(memberCtx, templateVariant{
				Filename:     memberCtx.Filename,
				Format:       memberCtx.Format,
				ContentStyle: member.ContentStyle,
			})
		}
		if err := os.WriteFile(memberPath, content, 0o644); err != nil {
			panic(fmt.Sprintf("build wim: write %s: %v", member.Path, err))
		}
		if err := os.Chtimes(memberPath, archiveTimestamp, archiveTimestamp); err != nil {
			panic(fmt.Sprintf("build wim: chtimes %s: %v", member.Path, err))
		}
	}
	filepath.Walk(tmpDir, func(current string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		_ = os.Chtimes(current, archiveTimestamp, archiveTimestamp)
		return nil
	})

	tmpWIM, err := os.CreateTemp("", "snablr-seed-*.wim")
	if err != nil {
		panic(fmt.Sprintf("build wim: temp file: %v", err))
	}
	tmpWIMPath := tmpWIM.Name()
	_ = tmpWIM.Close()
	defer os.Remove(tmpWIMPath)

	cmd := exec.Command("wimlib-imagex", "capture", tmpDir, tmpWIMPath, "SnablrSeed", "--compress=none")
	if out, err := cmd.CombinedOutput(); err != nil {
		panic(fmt.Sprintf("build wim: capture: %v: %s", err, strings.TrimSpace(string(out))))
	}

	data, err := os.ReadFile(tmpWIMPath)
	if err != nil {
		panic(fmt.Sprintf("build wim: read output: %v", err))
	}
	return data
}

func wimUnattendXML(ctx renderContext) []byte {
	return []byte(fmt.Sprintf(
		`<?xml version="1.0" encoding="utf-8"?><unattend><settings><component><UserData><ProductKey><Key>AAAAA-BBBBB-CCCCC-DDDDD-EEEEE</Key></ProductKey></UserData><AutoLogon><Username>%s</Username><AutoLogonPassword>%s</AutoLogonPassword></AutoLogon><Identification><Credentials><DomainAdmin>%s</DomainAdmin><DomainAdminPassword>%s</DomainAdminPassword></Credentials></Identification></component></settings></unattend>`,
		serviceAccountValue(ctx),
		dbPasswordValue(ctx),
		serviceAccountValue(ctx),
		dbPasswordValue(ctx),
	))
}

func wimBootstrapINI(ctx renderContext) []byte {
	return []byte(fmt.Sprintf("[Settings]\nPriority=Default\n[Default]\nDeployRoot=\\\\deploy-%s.example.invalid\\DeploymentShare$\nUserID=%s\nUserPassword=%s\n",
		ctx.Label,
		serviceAccountValue(ctx),
		dbPasswordValue(ctx),
	))
}

func wimCustomSettingsINI(ctx renderContext) []byte {
	return []byte(fmt.Sprintf("[Settings]\nPriority=Default\n[Default]\nDomainAdmin=%s\nDomainAdminPassword=%s\nMachineObjectOU=OU=Workstations,DC=%s,DC=local\n",
		serviceAccountValue(ctx),
		dbPasswordValue(ctx),
		strings.ToLower(strings.TrimSpace(ctx.Label)),
	))
}

func wimTaskSequenceXML(ctx renderContext) []byte {
	return []byte(fmt.Sprintf(
		`<?xml version="1.0" encoding="utf-8"?><sequence><step><name>Join Domain</name><Domain>%s.local</Domain><DomainAdmin>%s</DomainAdmin><DomainAdminPassword>%s</DomainAdminPassword></step></sequence>`,
		strings.ToLower(strings.TrimSpace(ctx.Label)),
		serviceAccountValue(ctx),
		dbPasswordValue(ctx),
	))
}
