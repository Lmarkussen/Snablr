package scanner

import (
	"testing"
)

// Task-sequence variables pair the OSD accounts with their passwords;
// OSDLocalAdminPassword is the local Administrator password.
func TestTaskSequenceVariablesArePaired(t *testing.T) {
	content := `<?xml version="1.0" encoding="utf-8"?><sequence version="3.10"><globalVarList><variable name="OSDJoinAccount" property="OSDJoinAccount">CORP\svc_osdjoin</variable><variable name="OSDJoinPassword" property="OSDJoinPassword">Osd-Join-Synth-4821</variable><variable name="OSDLocalAdminPassword" property="OSDLocalAdminPassword">Osd-Local-Synth-73</variable></globalVarList><group name="Capture"><step type="SMS_TaskSequence_CaptureSystemImageAction" name="Capture"><defaultVarList><variable name="OSDCaptureAccount" property="CaptureAccount">CORP\svc_capture</variable><variable name="OSDCaptureAccountPassword" property="CaptureAccountPassword">Osd-Capture-Synth-19</variable></defaultVarList></step></group></sequence>`
	findings, candidates := harvestAt(t, "Deploy/TaskSequences/WS-Build.xml", content)
	got := confirmedPairs(candidates)
	for _, want := range []harvestedPair{{`CORP\svc_osdjoin`, "Osd-Join-Synth-4821"}, {"Administrator", "Osd-Local-Synth-73"}, {`CORP\svc_capture`, "Osd-Capture-Synth-19"}} {
		if !got[want] {
			t.Errorf("missing confirmed %s / %s; confirmed=%v", want.identity, want.value, got)
		}
	}
	if !actionableRules(findings)[ConfirmedCredentialRuleID] {
		t.Errorf("no actionable confirmed-credential finding: %v", findingRuleSet(findings))
	}
}

// Network access account policy secrets and boot media variable files are
// protected material: reported for review, never actionable.
func TestSCCMProtectedMaterialIsReview(t *testing.T) {
	naa := `<?xml version="1.0" encoding="utf-16"?><Policy PolicyType="Machine" PolicySource="SMS:ABC"><PolicyRule><PolicyAction PolicyActionType="WMI-XML"><instance class="CCM_NetworkAccessAccount"><property name="NetworkAccessUsername" type="8"><value><![CDATA[<PolicySecret Version="1"><![CDATA[0601000001000000D08C9DDF0115D1118C7A00C04FC297EB0100000011]]]]><![CDATA[></PolicySecret>]]></value></property><property name="NetworkAccessPassword" type="8"><value><![CDATA[<PolicySecret Version="1"><![CDATA[0601000001000000D08C9DDF0115D1118C7A00C04FC297EB0100000022]]]]><![CDATA[></PolicySecret>]]></value></property></instance></PolicyAction></PolicyRule></Policy>`
	for _, tc := range []struct{ path, content, rule string }{
		{"Exports/Policy/NAAConfig.xml", naa, "content.sccm_naa_policy_secret"},
		{"Media/BootMedia/SMS/data/Variables.dat", "binary", "filename.sccm_media_variables"},
		{"RemoteInstall/SMSTemp/2026.01.01.00.00.00.0001.{00000000-1111-2222-3333-444444444444}.boot.var", "binary", "filename.sccm_pxe_boot_variables"},
	} {
		got := outcomeAt(t, newNoiseEngine(t), tc.path, tc.content)
		if !got.rules[tc.rule] {
			t.Errorf("%s not reported as %s: %v", tc.path, tc.rule, got.rules)
		}
		if len(got.actionable) > 0 {
			t.Errorf("%s is actionable: %v", tc.path, got.actionable)
		}
	}
	if got := outcomeAt(t, newNoiseEngine(t), "Users/alice/AppData/Local/Game/Variables.dat", "binary"); got.rules["filename.sccm_media_variables"] {
		t.Error("Variables.dat outside boot media reported")
	}
}
