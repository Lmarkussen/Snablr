package credentialanalysis

import (
	"regexp"
	"strings"
)

// Windows administration commands carry a password as a positional
// argument rather than behind a switch, so the switch-based command pairing
// cannot see it:
//
//	net use Z: \\server\share Password /user:DOMAIN\account
//	net use \\server\share /user:DOMAIN\account Password
//	net user account Password /add
//
// PowerShell builds credentials from a plaintext string:
//
//	New-Object PSCredential('DOMAIN\account', (ConvertTo-SecureString 'Password' -AsPlainText -Force))
//	$pw = ConvertTo-SecureString 'Password' -AsPlainText -Force; ... PSCredential('account', $pw)

func harvestWindowsCommands(text string, add func(Candidate)) {
	for _, line := range strings.Split(text, "\n") {
		tokens := commandTokens(strings.TrimSpace(line))
		for index := 0; index+1 < len(tokens); index++ {
			if !isNetCommand(tokens[index]) {
				continue
			}
			switch strings.ToLower(tokens[index+1]) {
			case "use":
				harvestNetUse(tokens[index+2:], add)
			case "user":
				harvestNetUser(tokens[index+2:], add)
			}
			break
		}
	}
	harvestPSCredentials(text, add)
}

func isNetCommand(token string) bool {
	switch strings.ToLower(strings.TrimSuffix(strings.ToLower(token), ".exe")) {
	case "net", "net1":
		return true
	default:
		return false
	}
}

// netArguments splits net command arguments into positional values and the
// /user: account. The command ends at a shell separator.
func netArguments(args []string) (positional []string, account string) {
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if arg == "&" || arg == "&&" || arg == "|" || arg == "||" || arg == ";" || arg == ">" || arg == ">>" {
			break
		}
		lower := strings.ToLower(arg)
		if strings.HasPrefix(lower, "/user:") || strings.HasPrefix(lower, "/u:") {
			account = arg[strings.Index(arg, ":")+1:]
			if account == "" && index+1 < len(args) {
				account = args[index+1]
				index++
			}
			continue
		}
		if strings.HasPrefix(arg, "/") {
			continue
		}
		positional = append(positional, arg)
	}
	return positional, strings.TrimSpace(account)
}

// harvestNetUse reads "net use [device] \\server\share [password] /user:account".
func harvestNetUse(args []string, add func(Candidate)) {
	positional, account := netArguments(args)
	if account == "" {
		return
	}
	var password string
	for _, value := range positional {
		switch {
		case value == "*" || strings.HasPrefix(value, `\\`) || isDriveDevice(value):
			continue
		case password == "":
			password = value
		default:
			return
		}
	}
	addCommandCredential(account, password, add)
}

// harvestNetUser reads "net user account password [/add] [/domain]".
func harvestNetUser(args []string, add func(Candidate)) {
	positional, _ := netArguments(args)
	if len(positional) != 2 {
		return
	}
	addCommandCredential(positional[0], positional[1], add)
}

func isDriveDevice(value string) bool {
	return len(value) == 2 && value[1] == ':' && (value[0]|0x20) >= 'a' && (value[0]|0x20) <= 'z'
}

func addCommandCredential(identity, password string, add func(Candidate)) {
	identity, password = strings.TrimSpace(identity), strings.TrimSpace(password)
	if identity == "" || password == "" || password == "*" {
		return
	}
	if IsPlaceholderIdentity(identity) || IsPlaceholderValue(password) || looksCommandPlaceholder(identity) || looksCommandPlaceholder(password) || looksReferenceOrTemplate(identity) || looksReferenceOrTemplate(password) {
		return
	}
	add(Candidate{Verification: Confirmed, CredentialType: "password", Identity: identity, Value: password, ValidationBasis: "explicit command invocation"})
}

var (
	// ConvertTo-SecureString 'x' -AsPlainText, optionally -String 'x'.
	secureStringLiteral = `ConvertTo-SecureString\s+(?:-String\s+)?(?:'([^']*)'|"([^"]*)")\s+-AsPlainText`
	// PSCredential('account', (ConvertTo-SecureString 'x' -AsPlainText ...)),
	// also via -ArgumentList and [pscredential]::new(...).
	inlinePSCredentialPattern = regexp.MustCompile(`(?i)PSCredential\]?(?:::new)?\s*(?:\(|-ArgumentList\s+)\s*(?:'([^']+)'|"([^"]+)")\s*,\s*\(?\s*` + secureStringLiteral)
	// $var = ConvertTo-SecureString 'x' -AsPlainText ...
	secureStringAssignmentPattern = regexp.MustCompile(`(?i)\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*` + secureStringLiteral)
	// PSCredential('account', $var)
	variablePSCredentialPattern = regexp.MustCompile(`(?i)PSCredential\]?(?:::new)?\s*(?:\(|-ArgumentList\s+)\s*(?:'([^']+)'|"([^"]+)")\s*,\s*\$([A-Za-z_][A-Za-z0-9_]*)`)
)

func harvestPSCredentials(text string, add func(Candidate)) {
	if !strings.Contains(strings.ToLower(text), "pscredential") {
		return
	}
	for _, match := range inlinePSCredentialPattern.FindAllStringSubmatch(text, -1) {
		addCommandCredential(firstNonEmpty(match[1], match[2]), firstNonEmpty(match[3], match[4]), add)
	}
	secure := map[string]string{}
	for _, match := range secureStringAssignmentPattern.FindAllStringSubmatch(text, -1) {
		secure[strings.ToLower(match[1])] = firstNonEmpty(match[2], match[3])
	}
	for _, match := range variablePSCredentialPattern.FindAllStringSubmatch(text, -1) {
		if password, ok := secure[strings.ToLower(match[3])]; ok {
			addCommandCredential(firstNonEmpty(match[1], match[2]), password, add)
		}
	}
}
