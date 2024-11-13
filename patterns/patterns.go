// SPDX-FileCopyrightText: Copyright 2023 Stacklok
// SPDX-License-Identifier: Apache-2.0

// Package patterns provides common patterns for secret detection
package patterns

import (
	"math"
	"strings"
)

// Common patterns for secret detection
var (
	// API key patterns
	CommonAPIPatterns = map[string]string{
		"aws_access_key":               `(?i)(?:^|[^A-Za-z0-9/])AKIA[0-9A-Z]{16}(?:[^A-Za-z0-9/]|$)`,
		"aws_secret":                   `(?i)(?:^|[^A-Za-z0-9/])"?([0-9a-zA-Z/+]{40})"?(?:[^A-Za-z0-9/]|$)`,
		"github_token":                 `(?i)(?:^|[^A-Za-z0-9/])gh[pousr]_[A-Za-z0-9_]{36}(?:[^A-Za-z0-9/]|$)`,
		"google_api":                   `(?i)(?:^|[^A-Za-z0-9/])AIza[0-9A-Za-z\-_]{35}(?:[^A-Za-z0-9/]|$)`,
		"stripe_key":                   `(?i)(?:^|[^A-Za-z0-9/])sk_live_[0-9a-zA-Z]{24}(?:[^A-Za-z0-9/]|$)`,
		"slack_token":                  `(?i)(?:^|[^A-Za-z0-9/])xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}(?:[^A-Za-z0-9/]|$)`,
		"twitter_bearer_token":         `(?i)(?:^|[^A-Za-z0-9/])AAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9]{38}(?:[^A-Za-z0-9/]|$)`,
		"facebook_access_token":        `(?i)(?:^|[^A-Za-z0-9/])EAACEdEose0cBA[0-9A-Za-z]+(?:[^A-Za-z0-9/]|$)`,
		"azure_storage_account_key":    `(?i)(?:^|[^A-Za-z0-9/])[a-zA-Z0-9/+]{88}(?:[^A-Za-z0-9/]|$)`,
		"digitalocean_access_token":    `(?i)(?:^|[^A-Za-z0-9/])[0-9a-f]{64}(?:[^A-Za-z0-9/]|$)`,
		"heroku_api_key":               `(?i)(?:^|[^A-Za-z0-9/])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?:[^A-Za-z0-9/]|$)`,
		"generic_api_key":              `(?i)(?:^|[^A-Za-z0-9/])api[_-]?key[_-]?[0-9a-zA-Z]{16,}(?:[^A-Za-z0-9/]|$)`,
		"sendgrid_api_key":             `(?i)(?:^|[^A-Za-z0-9/])SG\.[a-zA-Z0-9_-]{22,64}(?:[^A-Za-z0-9/]|$)`,
		"twilio_api_key":               `(?i)(?:^|[^A-Za-z0-9/])SK[a-z0-9]{32}(?:[^A-Za-z0-9/]|$)`,
		"mailgun_api_key":              `(?i)(?:^|[^A-Za-z0-9/])key-[0-9a-zA-Z]{32}(?:[^A-Za-z0-9/]|$)`,
		"paypal_bearer_token":          `(?i)(?:^|[^A-Za-z0-9/])access_token\$production\$[a-z0-9]{1,}\$[a-f0-9]{32}(?:[^A-Za-z0-9/]|$)`,
		"firebase_api_key":             `(?i)(?:^|[^A-Za-z0-9/])AIza[0-9A-Za-z\-_]{35}(?:[^A-Za-z0-9/]|$)`,
		"square_access_token":          `(?i)(?:^|[^A-Za-z0-9/])sq0atp-[0-9A-Za-z\-_]{22,43}(?:[^A-Za-z0-9/]|$)`,
		"shopify_access_token":         `(?i)(?:^|[^A-Za-z0-9/])shpca_[0-9a-fA-F]{32}(?:[^A-Za-z0-9/]|$)`,
		"pinterest_access_token":       `(?i)(?:^|[^A-Za-z0-9/])[A-Za-z0-9]{64}(?:[^A-Za-z0-9/]|$)`,
		"asana_personal_access_token":  `(?i)(?:^|[^A-Za-z0-9/])1/[0-9a-f]{32}(?:[^A-Za-z0-9/]|$)`,
		"gitlab_personal_access_token": `(?i)(?:^|[^A-Za-z0-9/])glpat-[0-9A-Za-z\-_]{20}(?:[^A-Za-z0-9/]|$)`,
		"dropbox_access_token":         `(?i)(?:^|[^A-Za-z0-9/])sl\.[a-zA-Z0-9_-]{11,120}(?:[^A-Za-z0-9/]|$)`,
		"microsoft_graph_access_token": `(?i)(?:^|[^A-Za-z0-9/])eyJ[a-zA-Z0-9-_]+\.eyJ[a-zA-Z0-9-_]+(?:[^A-Za-z0-9/]|$)`,
		"bitbucket_access_token":       `(?i)(?:^|[^A-Za-z0-9/])[A-Za-z0-9_]{43}(?:[^A-Za-z0-9/]|$)`,
		"huggingface_token":            `(?i)(?:^|[^A-Za-z0-9/])hf_[A-Za-z0-9]{32,}(?:[^A-Za-z0-9/]|$)`,
	}

	// Password patterns
	PasswordPatterns = map[string]string{
		"basic_password":   `(?i)password['":\s]*[=:]\s*['"]?[^\s'"]{8,}['"]?`,
		"complex_password": `(?i)"?([A-Za-z\d@$!%*#?&]{8,})"?`, // Updated pattern to capture entire password
	}

	// Private key patterns
	PrivateKeyPatterns = map[string]string{
		"rsa_private":       `-----BEGIN RSA PRIVATE KEY-----`,
		"ssh_private":       `-----BEGIN OPENSSH PRIVATE KEY-----`,
		"pgp_private":       `-----BEGIN PGP PRIVATE KEY BLOCK-----`,
		"generic_private":   `-----BEGIN PRIVATE KEY-----`,
		"dsa_private":       `-----BEGIN DSA PRIVATE KEY-----`,
		"ec_private":        `-----BEGIN EC PRIVATE KEY-----`,
		"putty_private":     `PuTTY-User-Key-File-2: ssh-rsa`,
		"jwt_private":       `(?i)-----BEGIN PRIVATE KEY-----\s*\n*.*[A-Za-z0-9+/=\s]*-----END PRIVATE KEY-----`, // JWT format may vary
		"pkcs8_private":     `-----BEGIN ENCRYPTED PRIVATE KEY-----`,
		"pem_certificate":   `-----BEGIN CERTIFICATE-----`, // Matches PEM certificates which may contain private keys in bundles
		"pkcs12_private":    `(?i)\.p12$|\.pfx$`,           // Often PKCS#12 files end with .p12 or .pfx extensions
		"putty_ppk_private": `(?i)\.ppk$`,                  // PuTTY PPK private key files
		"cosign_private":    `-----BEGIN COSIGN PRIVATE KEY-----`,
		"sigstore_private":  `(?i)-----BEGIN SIGSTORE PRIVATE KEY-----`,
	}
)

// EntropyThresholds defines minimum entropy values for different types of secrets
var EntropyThresholds = map[string]float64{
	"api_key":     4.5,
	"password":    4.0,
	"private_key": 5.0,
}

// CalculateEntropy calculates Shannon entropy for a given string
func CalculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	charCount := make(map[rune]int)
	for _, c := range s {
		charCount[c]++
	}

	entropy := 0.0
	length := float64(len(s))
	for _, count := range charCount {
		freq := float64(count) / length
		entropy -= freq * math.Log2(freq)
	}

	return entropy
}

// IsLikelySecret evaluates if a string is likely to be a secret based on entropy and patterns
func IsLikelySecret(s string, entropyThreshold float64) bool {
	// Skip if too short or too long
	if len(s) < 8 || len(s) > 100 {
		return false
	}

	// Skip if contains common words
	commonWords := []string{"password", "secret", "key", "token"}
	lower := strings.ToLower(s)
	for _, word := range commonWords {
		if word == lower {
			return false
		}
	}

	// Check entropy
	entropy := CalculateEntropy(s)
	if entropy < entropyThreshold {
		return false
	}

	// Check character diversity
	hasUpper := strings.ContainsAny(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	hasLower := strings.ContainsAny(s, "abcdefghijklmnopqrstuvwxyz")
	hasDigit := strings.ContainsAny(s, "0123456789")
	hasSpecial := strings.ContainsAny(s, "!@#$%^&*()_+-=[]{}|;:,.<>?")

	// Require at least 3 character types for high entropy strings
	characterTypes := 0
	if hasUpper {
		characterTypes++
	}
	if hasLower {
		characterTypes++
	}
	if hasDigit {
		characterTypes++
	}
	if hasSpecial {
		characterTypes++
	}

	return characterTypes >= 3
}

// GetAllPatterns returns all available patterns
func GetAllPatterns() map[string]string {
	patterns := make(map[string]string)

	// Combine all pattern maps
	for k, v := range CommonAPIPatterns {
		patterns[k] = v
	}
	for k, v := range PasswordPatterns {
		patterns[k] = v
	}
	for k, v := range PrivateKeyPatterns {
		patterns[k] = v
	}

	return patterns
}
