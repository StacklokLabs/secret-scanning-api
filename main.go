// SPDX-FileCopyrightText: Copyright 2023 Stacklok
// SPDX-License-Identifier: Apache-2.0

// Package main provides a command-line tool to scan for secrets in text / files.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/stackloklabs/secret-scanning-api/patterns"
	"github.com/stackloklabs/secret-scanning-api/scanner"
)

type scanFilters struct {
	enablePasswords   bool
	enableAPIKeys     bool
	enablePrivateKeys bool
}

func main() {
	var (
		file        string
		text        string
		showHelp    bool
		entropyOnly bool
		maskSecrets bool
		filters     scanFilters
	)

	// File and general flags
	flag.StringVar(&file, "file", "", "File to scan for secrets")
	flag.StringVar(&text, "text", "", "Text to scan for secrets")
	flag.BoolVar(&entropyOnly, "entropy-only", false, "Use only entropy-based detection")
	flag.BoolVar(&maskSecrets, "mask", true, "Mask secrets in output")
	flag.BoolVar(&showHelp, "help", false, "Show help message")

	// Pattern type flags
	flag.BoolVar(&filters.enablePasswords, "passwords", true, "Enable password detection")
	flag.BoolVar(&filters.enableAPIKeys, "apikeys", true, "Enable API key detection")
	flag.BoolVar(&filters.enablePrivateKeys, "privatekeys", true, "Enable private key detection")

	flag.Parse()

	if showHelp {
		printUsage()
		return
	}

	// Initialize scanner
	s := scanner.New()

	// Add patterns unless entropy-only mode is enabled
	if !entropyOnly {
		addPatternsWithFilters(s, filters)
	}

	var input string
	var err error

	switch {
	case file != "":
		input, err = readFile(file)
	case text != "":
		input = text
	default:
		input, err = readStdin()
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		os.Exit(1)
	}

	// Perform scan
	results, err := s.Scan(context.Background(), input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning: %v\n", err)
		os.Exit(1)
	}

	// Print results
	if len(results) == 0 {
		fmt.Println("No secrets detected")
		return
	}

	fmt.Printf("Found %d potential secrets:\n\n", len(results))
	for i, result := range results {
		fmt.Printf("%d. Type: %s\n", i+1, result.Type)
		fmt.Printf("   Description: %s\n", result.Description)
		fmt.Printf("   Confidence: %.2f\n", result.Confidence)
		fmt.Printf("   Value: %s\n", scanner.MaskSecret(result.Value, 2)) // Updated to include exposeCount
		fmt.Printf("   Position: %d-%d\n", result.StartIndex, result.EndIndex)
		fmt.Printf("   Line Number: %d\n", result.LineNumber)
		fmt.Println()
	}
}

func addPatternsWithFilters(s *scanner.Scanner, filters scanFilters) {
	if filters.enableAPIKeys {
		for name, pattern := range patterns.CommonAPIPatterns {
			if err := s.AddPattern(name, pattern); err != nil {
				fmt.Fprintf(os.Stderr, "Error adding API pattern %s: %v\n", name, err)
			}
		}
	}

	if filters.enablePasswords {
		for name, pattern := range patterns.PasswordPatterns {
			if err := s.AddPattern(name, pattern); err != nil {
				fmt.Fprintf(os.Stderr, "Error adding password pattern %s: %v\n", name, err)
			}
		}
	}

	if filters.enablePrivateKeys {
		for name, pattern := range patterns.PrivateKeyPatterns {
			if err := s.AddPattern(name, pattern); err != nil {
				fmt.Fprintf(os.Stderr, "Error adding private key pattern %s: %v\n", name, err)
			}
		}
	}
}

func readFile(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}
	return string(content), nil
}

func readStdin() (string, error) {
	var builder strings.Builder
	reader := bufio.NewReader(os.Stdin)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", fmt.Errorf("failed to read from stdin: %w", err)
		}
		builder.WriteString(line)
	}

	return builder.String(), nil
}

func printUsage() {
	fmt.Println(`Secret Scanner - Detect potential secrets in text

Usage:
  secret-scanner [options]

Options:
  -file string
        File to scan for secrets
  -text string
        Text to scan for secrets
  -entropy-only
        Use only entropy-based detection
  -mask
        Mask secrets in output (default: true)
  -passwords
        Enable password detection (default: true)
  -apikeys
        Enable API key detection (default: true)
  -privatekeys
        Enable private key detection (default: true)
  -help
        Show this help message

Examples:
  # Scan a file
  secret-scanner -file config.json

  # Scan without password detection
  secret-scanner -file config.json -passwords=false

  # Scan only for API keys
  secret-scanner -file config.json -passwords=false -privatekeys=false

  # Scan text directly without masking
  secret-scanner -text "api_key=1234567890abcdef" -mask=false

  # Scan from stdin
  cat config.json | secret-scanner

  # Use only entropy-based detection
  secret-scanner -entropy-only -file config.json

Note: Boolean flags require the '=' operator, e.g., -mask=false instead of -mask false`)
}
