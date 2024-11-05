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

func main() {
	var (
		file        string
		text        string
		showHelp    bool
		entropyOnly bool
	)

	flag.StringVar(&file, "file", "", "File to scan for secrets")
	flag.StringVar(&text, "text", "", "Text to scan for secrets")
	flag.BoolVar(&entropyOnly, "entropy-only", false, "Use only entropy-based detection")
	flag.BoolVar(&showHelp, "help", false, "Show help message")
	flag.Parse()

	if showHelp {
		printUsage()
		return
	}

	// Initialize scanner
	s := scanner.New()

	// Add patterns unless entropy-only mode is enabled
	if !entropyOnly {
		for name, pattern := range patterns.GetAllPatterns() {
			if err := s.AddPattern(name, pattern); err != nil {
				fmt.Fprintf(os.Stderr, "Error adding pattern %s: %v\n", name, err)
				os.Exit(1)
			}
		}
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
		fmt.Printf("   Value: %s\n", maskSecret(result.Value))
		fmt.Printf("   Position: %d-%d\n", result.StartIndex, result.EndIndex)
		fmt.Println()
	}
}

func readFile(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
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
			return "", err
		}
		builder.WriteString(line)
	}

	return builder.String(), nil
}

func maskSecret(secret string) string {
	if len(secret) <= 4 {
		return strings.Repeat("*", len(secret))
	}
	return secret[:2] + strings.Repeat("*", len(secret)-4) + secret[len(secret)-2:]
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
  -help
        Show this help message

Examples:
  # Scan a file
  secret-scanner -file config.json

  # Scan text directly
  secret-scanner -text "api_key=1234567890abcdef"

  # Scan from stdin
  cat config.json | secret-scanner

  # Use only entropy-based detection
  secret-scanner -entropy-only -file config.json`)
}
