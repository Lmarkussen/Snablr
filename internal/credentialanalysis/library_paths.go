package credentialanalysis

import (
	"regexp"
	"strings"
)

// Installed third-party library code (Python site-packages and standard
// library, Node modules) is full of documentation examples and test
// fixtures that look like credentials ("admin" / "SomeSecretPassword" in
// module docs). It is not the operator's or the organisation's data, so
// credential material found there is review material, never confirmed.

var pythonRuntimeSegment = regexp.MustCompile(`^python[0-9]+(?:\.?[0-9]+)?$`)

var libraryDirectories = map[string]struct{}{
	"site-packages": {}, "dist-packages": {}, "node_modules": {}, "bower_components": {},
}

// ThirdPartyLibraryPath reports whether a share path (or archive member
// path) lies inside installed third-party or runtime library code.
func ThirdPartyLibraryPath(path string) bool {
	normalized := strings.ToLower(strings.NewReplacer(`\`, "/", "!", "/").Replace(path))
	segments := strings.Split(normalized, "/")
	for index, segment := range segments {
		if _, ok := libraryDirectories[segment]; ok {
			return true
		}
		// The Python standard library: lib/python3.12/... on Unix and
		// Python312/Lib/... on Windows.
		if pythonRuntimeSegment.MatchString(segment) {
			if index > 0 && segments[index-1] == "lib" {
				return true
			}
			if index+1 < len(segments) && segments[index+1] == "lib" {
				return true
			}
		}
	}
	return false
}

// dpapiProviderHex and dpapiBlobBase64 identify a DPAPI blob: the provider
// GUID df9d8cd0-1501-11d1-8c7a-00c04fc297eb in hex, and the start of a blob
// (version 1 + provider GUID) in base64.
const (
	dpapiProviderHex = "d08c9ddf0115d1118c7a00c04fc297eb"
	dpapiBlobBase64  = "AQAAANCMnd8BFdERjHoAwE/Cl+s"
)

// IsDPAPIBlob reports whether a value is DPAPI-protected material, which is
// bound to a user or machine key and is never plaintext.
func IsDPAPIBlob(value string) bool {
	trimmed := strings.TrimSpace(value)
	return strings.HasPrefix(trimmed, dpapiBlobBase64) || strings.Contains(strings.ToLower(trimmed), dpapiProviderHex)
}
