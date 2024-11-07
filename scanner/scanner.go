// SPDX-FileCopyrightText: Copyright 2023 Stacklok
// SPDX-License-Identifier: Apache-2.0

// Package scanner provides a secret scanning library
package scanner

import (
	"bufio"
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"
)

// Result represents a detected secret in the text
type Result struct {
	Type        string  `json:"type"`
	Value       string  `json:"value"`
	StartIndex  int     `json:"start_index"`
	EndIndex    int     `json:"end_index"`
	LineNumber  int     `json:"line_number"`
	Confidence  float64 `json:"confidence"`
	Description string  `json:"description"`
}

// Scanner represents the main secret scanning interface
type Scanner struct {
	patterns     map[string]*regexp.Regexp
	patternMutex sync.RWMutex
	cache        *sync.Map
	workers      int
}

// ScannerOption represents a function that modifies Scanner configuration
type ScannerOption func(*Scanner)

// WithWorkers sets the number of concurrent workers for pattern matching
func WithWorkers(n int) ScannerOption {
	return func(s *Scanner) {
		if n > 0 {
			s.workers = n
		}
	}
}

// New creates a new Scanner instance with default patterns
func New(opts ...ScannerOption) *Scanner {
	s := &Scanner{
		patterns: make(map[string]*regexp.Regexp),
		cache:    &sync.Map{},
		workers:  4, // default number of workers
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// AddPattern adds a new pattern to the scanner
func (s *Scanner) AddPattern(name string, pattern string) error {
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	s.patternMutex.Lock()
	defer s.patternMutex.Unlock()
	s.patterns[name] = compiled
	return nil
}

// scanChunk performs pattern matching on a chunk of text
func (s *Scanner) scanChunk(ctx context.Context, chunk string, offset int) ([]Result, error) {
	var results []Result
	s.patternMutex.RLock()
	defer s.patternMutex.RUnlock()

	for patternName, pattern := range s.patterns {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		matches := pattern.FindAllStringIndex(chunk, -1)
		for _, match := range matches {
			lineNumber := strings.Count(chunk[:match[0]], "\n") + 1
			result := Result{
				Type:        patternName,
				Value:       chunk[match[0]:match[1]],
				StartIndex:  offset + match[0],
				EndIndex:    offset + match[1],
				LineNumber:  lineNumber,
				Confidence:  calculateConfidence(chunk[match[0]:match[1]]),
				Description: getDescription(patternName),
			}
			results = append(results, result)
		}
	}

	// Group results by line number and select the highest confidence result
	lineResults := make(map[int]Result)
	for _, result := range results {
		if existing, found := lineResults[result.LineNumber]; !found || result.Confidence > existing.Confidence {
			lineResults[result.LineNumber] = result
		}
	}

	// Convert the map back to a slice
	finalResults := make([]Result, 0, len(lineResults))
	for _, result := range lineResults {
		finalResults = append(finalResults, result)
	}

	return finalResults, nil
}

// Scan performs the secret scanning on the provided text
func (s *Scanner) Scan(ctx context.Context, text string) ([]Result, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Check cache first
	if cached, ok := s.cache.Load(text); ok {
		return cached.([]Result), nil
	}

	// For small texts, process directly
	if len(text) < 10000 { // threshold for small texts
		results, err := s.scanChunk(ctx, text, 0)
		if err != nil {
			return nil, err
		}
		s.cache.Store(text, results)
		return results, nil
	}

	// For larger texts, process in parallel chunks
	chunks := s.splitIntoChunks(text)
	resultsChan := make(chan []Result, len(chunks))
	errChan := make(chan error, 1)
	var wg sync.WaitGroup
	sem := make(chan struct{}, s.workers) // semaphore for worker pool

	// Start workers
	for _, chunk := range chunks {
		wg.Add(1)
		go func(chunkText string, offset int) {
			defer wg.Done()
			sem <- struct{}{}        // acquire semaphore
			defer func() { <-sem }() // release semaphore

			results, err := s.scanChunk(ctx, chunkText, offset)
			if err != nil {
				select {
				case errChan <- err:
				default:
				}
				return
			}

			select {
			case resultsChan <- results:
			case <-ctx.Done():
				select {
				case errChan <- ctx.Err():
				default:
				}
			}
		}(chunk.text, chunk.offset)
	}

	// Wait for all workers in a separate goroutine
	go func() {
		wg.Wait()
		close(resultsChan)
		close(errChan)
	}()

	// Collect results
	var allResults []Result
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case err := <-errChan:
			if err != nil {
				return nil, err
			}
		case results, ok := <-resultsChan:
			if !ok {
				// Channel closed, all workers completed
				s.cache.Store(text, allResults)
				return allResults, nil
			}
			allResults = append(allResults, results...)
		}
	}
}

// StreamScan performs streaming scan on a reader
func (s *Scanner) StreamScan(ctx context.Context, reader *strings.Reader) (<-chan Result, error) {
	resultsChan := make(chan Result, 100)
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024*10) // 10MB max line size

	go func() {
		defer close(resultsChan)

		offset := 0
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
			}

			line := scanner.Text()
			results, err := s.scanChunk(ctx, line, offset)
			if err != nil {
				return
			}

			for _, result := range results {
				select {
				case <-ctx.Done():
					return
				case resultsChan <- result:
				}
			}
			offset += len(line) + 1 // +1 for newline
		}
	}()

	return resultsChan, nil
}

type chunk struct {
	text   string
	offset int
}

func (s *Scanner) splitIntoChunks(text string) []chunk {
	const chunkSize = 10000
	var chunks []chunk

	for i := 0; i < len(text); i += chunkSize {
		end := i + chunkSize
		if end > len(text) {
			end = len(text)
		}
		chunks = append(chunks, chunk{
			text:   text[i:end],
			offset: i,
		})
	}

	return chunks
}

func calculateConfidence(secret string) float64 {
	// TODO: Implement more sophisticated confidence scoring
	// Current implementation is a basic entropy-based score
	var entropy float64 = 0.8 // Default high confidence
	if len(secret) < 8 {
		entropy *= 0.5
	}
	return entropy
}

func getDescription(patternType string) string {
	descriptions := map[string]string{
		"aws_access_key":               "Possible AWS access key detected",
		"aws_secret":                   "Possible AWS secret access key detected",
		"github_token":                 "Possible GitHub token detected",
		"google_api":                   "Possible Google API key detected",
		"stripe_key":                   "Possible Stripe API key detected",
		"slack_token":                  "Possible Slack token detected",
		"twitter_bearer_token":         "Possible Twitter bearer token detected",
		"facebook_access_token":        "Possible Facebook access token detected",
		"azure_storage_account_key":    "Possible Azure Storage account key detected",
		"digitalocean_access_token":    "Possible DigitalOcean access token detected",
		"heroku_api_key":               "Possible Heroku API key detected",
		"sendgrid_api_key":             "Possible SendGrid API key detected",
		"twilio_api_key":               "Possible Twilio API key detected",
		"mailgun_api_key":              "Possible Mailgun API key detected",
		"paypal_bearer_token":          "Possible PayPal bearer token detected",
		"firebase_api_key":             "Possible Firebase API key detected",
		"square_access_token":          "Possible Square access token detected",
		"shopify_access_token":         "Possible Shopify access token detected",
		"pinterest_access_token":       "Possible Pinterest access token detected",
		"asana_personal_access_token":  "Possible Asana personal access token detected",
		"gitlab_personal_access_token": "Possible GitLab personal access token detected",
		"twitch_access_token":          "Possible Twitch access token detected",
		"dropbox_access_token":         "Possible Dropbox access token detected",
		"microsoft_graph_access_token": "Possible Microsoft Graph access token detected",
		"bitbucket_access_token":       "Possible Bitbucket access token detected",
		"huggingface_token":            "Possible Hugging Face token detected",
		"rsa_private":                  "Possible RSA private key detected",
		"ssh_private":                  "Possible SSH private key detected",
		"pgp_private":                  "Possible PGP private key detected",
		"generic_private":              "Possible generic private key detected",
		"dsa_private":                  "Possible DSA private key detected",
		"ec_private":                   "Possible EC private key detected",
		"putty_private":                "Possible PuTTY private key detected",
		"jwt_private":                  "Possible JWT private key detected",
		"pkcs8_private":                "Possible PKCS8 private key detected",
		"pem_certificate":              "Possible PEM certificate detected",
		"pkcs12_private":               "Possible PKCS12 private key detected",
		"cosign_private":               "Possible Cosign private key detected",
		"sigstore_private":             "Possible Sigstore private key detected",
		"complex_password":             "Possible complex password detected",
	}

	if desc, ok := descriptions[patternType]; ok {
		return desc
	}
	return "Unknown secret type detected"
}

// ErrContextCancelled is returned when the context is cancelled
var ErrContextCancelled = errors.New("operation cancelled by context")
