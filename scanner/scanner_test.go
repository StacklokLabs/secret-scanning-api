// SPDX-FileCopyrightText: Copyright 2023 Stacklok
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestScanner(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		patterns map[string]string
		want     int // number of expected results
	}{
		{
			name: "AWS Key Detection",
			text: "AKIAIOSFODNN7EXAMPLE\nAKIAI44QH8DHBEXAMPLE",
			patterns: map[string]string{
				"aws_key": `(?i)AKIA[0-9A-Z]{16}`,
			},
			want: 2,
		},
		{
			name: "Password Detection",
			text: "password='SuperSecret123!'",
			patterns: map[string]string{
				"password": `(?i)password['":\s]*[=:]\s*['"]?[^\s'"]{8,}['"]?`,
			},
			want: 1,
		},
		{
			name: "No Secrets",
			text: "This is a normal text without any secrets",
			patterns: map[string]string{
				"test": `secret[0-9]+`,
			},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New()
			for name, pattern := range tt.patterns {
				if err := s.AddPattern(name, pattern); err != nil {
					t.Fatalf("Failed to add pattern: %v", err)
				}
			}

			results, err := s.Scan(context.Background(), tt.text)
			if err != nil {
				t.Fatalf("Scan failed: %v", err)
			}

			if got := len(results); got != tt.want {
				t.Errorf("Scanner.Scan() got %v results, want %v", got, tt.want)
			}
		})
	}
}

func TestScannerCancellation(t *testing.T) {
	s := New()
	err := s.AddPattern("test", `[a-z]+`)
	if err != nil {
		t.Fatalf("Failed to add pattern: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err = s.Scan(ctx, "test text")
	if err == nil {
		t.Error("Expected error due to cancelled context, got nil")
	}
}

func TestScannerCache(t *testing.T) {
	s := New()
	err := s.AddPattern("test", `secret[0-9]+`)
	if err != nil {
		t.Fatalf("Failed to add pattern: %v", err)
	}

	text := "This contains secret123 and secret456"

	// First scan
	results1, err := s.Scan(context.Background(), text)
	if err != nil {
		t.Fatalf("First scan failed: %v", err)
	}

	// Second scan (should use cache)
	results2, err := s.Scan(context.Background(), text)
	if err != nil {
		t.Fatalf("Second scan failed: %v", err)
	}

	if len(results1) != len(results2) {
		t.Errorf("Cache returned different results: got %v results, want %v", len(results2), len(results1))
	}
}

// Benchmarks

func generateLargeText(size int) string {
	// Generate text with some secrets
	template := `
	{
		"aws_key": "AKIAIOSFODNN7EXAMPLE",
		"password": "SuperSecret123!",
		"normal_text": "This is just some regular text to add volume",
		"api_key": "sk_live_1234567890abcdefghijklmn"
	}`

	var builder strings.Builder
	for builder.Len() < size {
		builder.WriteString(template)
	}
	return builder.String()
}

func BenchmarkScanner(b *testing.B) {
	patterns := map[string]string{
		"aws_key":  `(?i)AKIA[0-9A-Z]{16}`,
		"password": `(?i)password['":\s]*[=:]\s*['"]?[^\s'"]{8,}['"]?`,
		"api_key":  `sk_live_[0-9a-zA-Z]{24}`,
	}

	texts := map[string]string{
		"small":  generateLargeText(1000),
		"medium": generateLargeText(100000),
		"large":  generateLargeText(1000000),
	}

	workers := []int{1, 4, 8, 16}

	for name, text := range texts {
		b.Run(name, func(b *testing.B) {
			for _, numWorkers := range workers {
				b.Run(fmt.Sprintf("%d_workers", numWorkers), func(b *testing.B) {
					s := New(WithWorkers(numWorkers))
					for name, pattern := range patterns {
						s.AddPattern(name, pattern)
					}

					ctx := context.Background()
					b.ResetTimer()

					for i := 0; i < b.N; i++ {
						_, err := s.Scan(ctx, text)
						if err != nil {
							b.Fatalf("Scan failed: %v", err)
						}
					}
				})
			}

			// Test streaming performance
			b.Run("streaming", func(b *testing.B) {
				s := New()
				for name, pattern := range patterns {
					s.AddPattern(name, pattern)
				}

				ctx := context.Background()
				b.ResetTimer()

				for i := 0; i < b.N; i++ {
					reader := strings.NewReader(text)
					resultsChan, err := s.StreamScan(ctx, reader)
					if err != nil {
						b.Fatalf("StreamScan failed: %v", err)
					}

					// Consume results
					for range resultsChan {
					}
				}
			})
		})
	}
}

func BenchmarkScannerCache(b *testing.B) {
	s := New()
	patterns := map[string]string{
		"aws_key":  `(?i)AKIA[0-9A-Z]{16}`,
		"password": `(?i)password['":\s]*[=:]\s*['"]?[^\s'"]{8,}['"]?`,
		"api_key":  `sk_live_[0-9a-zA-Z]{24}`,
	}

	for name, pattern := range patterns {
		s.AddPattern(name, pattern)
	}

	text := generateLargeText(100000)
	ctx := context.Background()

	// First scan to populate cache
	_, err := s.Scan(ctx, text)
	if err != nil {
		b.Fatalf("Initial scan failed: %v", err)
	}

	b.ResetTimer()

	// Benchmark cached access
	b.Run("cached", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := s.Scan(ctx, text)
			if err != nil {
				b.Fatalf("Cached scan failed: %v", err)
			}
		}
	})
}
