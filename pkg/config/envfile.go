package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const defaultEnvFile = ".env"

var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func loadDefaultEnvFile() {
	if explicit := strings.TrimSpace(os.Getenv("UNEARTH_ENV_FILE")); explicit != "" {
		loadOptionalEnvFile(explicit)
		return
	}

	// Preserve project-local behavior first, then fall back to the stable user
	// config location so an installed binary works from any working directory.
	// loadEnvFile never overwrites a non-empty process variable, and loading the
	// local file first gives it precedence over the user-wide default.
	for _, path := range defaultEnvFiles() {
		loadOptionalEnvFile(path)
	}
}

func loadOptionalEnvFile(path string) {
	if err := loadEnvFile(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		// API keys are optional; a malformed local env file should not make
		// discovery unusable. Operators can still export vars explicitly.
		return
	}
}

func defaultEnvFiles() []string {
	paths := []string{defaultEnvFile}

	configDir := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME"))
	if configDir == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return paths
		}
		configDir = filepath.Join(home, ".config")
	}
	userPath := filepath.Join(configDir, "unearth", defaultEnvFile)

	if absoluteLocal, err := filepath.Abs(defaultEnvFile); err == nil {
		if absoluteUser, err := filepath.Abs(userPath); err == nil && absoluteLocal == absoluteUser {
			return paths
		}
	}
	return append(paths, userPath)
}

func loadEnvFile(path string) error {
	f, err := os.Open(path) // #nosec G304 - env-file path is operator controlled.
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	scn := bufio.NewScanner(f)
	for lineNo := 1; scn.Scan(); lineNo++ {
		line := strings.TrimSpace(scn.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))

		name, raw, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("%s:%d: expected KEY=value", path, lineNo)
		}
		name = strings.TrimSpace(name)
		if !envNamePattern.MatchString(name) {
			return fmt.Errorf("%s:%d: invalid variable name %q", path, lineNo, name)
		}
		if os.Getenv(name) != "" {
			continue
		}

		value, err := parseEnvValue(raw)
		if err != nil {
			return fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
		if err := os.Setenv(name, value); err != nil {
			return fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
	}
	return scn.Err()
}

func parseEnvValue(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}

	if value[0] == '"' {
		end := closingQuoteIndex(value, '"')
		if end < 0 {
			return "", errors.New("unterminated quoted value")
		}
		if rest := strings.TrimSpace(value[end+1:]); rest != "" && !strings.HasPrefix(rest, "#") {
			return "", errors.New("unexpected content after quoted value")
		}
		return strconv.Unquote(value[:end+1])
	}
	if value[0] == '\'' {
		end := closingQuoteIndex(value, '\'')
		if end < 0 {
			return "", errors.New("unterminated quoted value")
		}
		if rest := strings.TrimSpace(value[end+1:]); rest != "" && !strings.HasPrefix(rest, "#") {
			return "", errors.New("unexpected content after quoted value")
		}
		return value[1:end], nil
	}
	if i := unquotedCommentIndex(value); i >= 0 {
		value = strings.TrimSpace(value[:i])
	}
	return value, nil
}

func closingQuoteIndex(s string, quote byte) int {
	for i := 1; i < len(s); i++ {
		if s[i] != quote {
			continue
		}
		if quote == '"' && i > 0 && s[i-1] == '\\' {
			continue
		}
		return i
	}
	return -1
}

func unquotedCommentIndex(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t') {
			return i
		}
	}
	return -1
}
