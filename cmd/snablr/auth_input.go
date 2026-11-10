package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

const maxPasswordFileSize = 1 << 20

func resolveCLIAuthPassword(value, path string, prompt, automatic bool, fs *flag.FlagSet, stdin *os.File, stderr io.Writer) (string, error) {
	valueSet, aliasSet := false, false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "password" {
			valueSet = true
		}
		if f.Name == "pass" {
			aliasSet = true
		}
	})
	fileSet := false
	fs.Visit(func(f *flag.Flag) { fileSet = fileSet || f.Name == "password-file" })
	if valueSet && aliasSet || (valueSet || aliasSet) && fileSet || (valueSet || aliasSet) && prompt || fileSet && prompt {
		return "", errors.New("conflicting password sources; use only one of --password/--pass, --password-file, or --password-prompt")
	}
	if fileSet {
		if path == "" {
			return "", errors.New("--password-file requires a path")
		}
		return readPasswordFile(path)
	}
	if prompt {
		return readInteractivePassword(stdin, stderr)
	}
	if valueSet || aliasSet {
		return value, nil
	}
	if automatic {
		return readInteractivePassword(stdin, stderr)
	}
	return value, nil
}

func readPasswordFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("cannot read password file: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", errors.New("cannot inspect password file")
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("password file must be a regular file")
	}
	if info.Mode().Perm()&0444 == 0 {
		return "", errors.New("password file is not readable")
	}
	if info.Size() > maxPasswordFileSize {
		return "", errors.New("password file exceeds the 1 MiB limit")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxPasswordFileSize+1))
	if err != nil {
		return "", errors.New("cannot read password file")
	}
	if len(b) > maxPasswordFileSize {
		return "", errors.New("password file exceeds the 1 MiB limit")
	}
	if len(b) >= 2 && b[len(b)-2] == '\r' && b[len(b)-1] == '\n' {
		b = b[:len(b)-2]
	} else if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	if len(b) == 0 {
		return "", errors.New("password file is empty")
	}
	if !utf8.Valid(b) || strings.IndexByte(string(b), 0) >= 0 {
		return "", errors.New("password file contains invalid password data")
	}
	return string(b), nil
}

func readInteractivePassword(stdin *os.File, stderr io.Writer) (string, error) {
	_ = stdin // stdin is deliberately never read: secrets must come from a terminal device.
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errors.New("password input requires an interactive terminal")
	}
	defer tty.Close()
	if !term.IsTerminal(int(tty.Fd())) {
		return "", errors.New("password input requires an interactive terminal")
	}
	if _, err := io.WriteString(stderr, "Password: "); err != nil {
		return "", errors.New("cannot display password prompt")
	}
	password, err := term.ReadPassword(int(tty.Fd()))
	_, _ = io.WriteString(stderr, "\n")
	if err != nil {
		return "", errors.New("password prompt cancelled or terminal input failed")
	}
	if len(password) == 0 {
		return "", errors.New("password cannot be empty")
	}
	return string(password), nil
}
