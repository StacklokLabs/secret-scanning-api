# Secret Scanning AI

A high-performance Go library for detecting secrets, passwords, and API tokens in text content. Uses both pattern matching and entropy-based detection for accurate results.

## Worker System

The scanner uses a worker pool pattern for parallel processing of large texts. This system provides:
- Concurrent pattern matching
- Controlled resource usage
- Optimal CPU utilization
- Configurable parallelism

### How Workers Function

1. **Text Chunking**:
   - Large texts are automatically split into chunks (default 10KB each)
   - Each chunk maintains its original position information
   ```go
   // Internal chunking mechanism
   type chunk struct {
       text   string
       offset int
   }
   ```

2. **Worker Pool**:
   - Workers are implemented using goroutines and a semaphore pattern
   - Each worker processes one chunk at a time
   - Results are collected through a channel
   ```go
   // Example of worker pool configuration
   scanner := scanner.New(scanner.WithWorkers(runtime.NumCPU()))
   ```

3. **Load Balancing**:
   - Chunks are distributed automatically among workers
   - Semaphore prevents worker overflow
   - Workers process chunks concurrently until all are complete

### Configuring Workers

1. **Default Configuration**:
   ```go
   // Creates scanner with default 4 workers
   scanner := scanner.New()
   ```

2. **Custom Worker Count**:
   ```go
   // Creates scanner with 8 workers
   scanner := scanner.New(scanner.WithWorkers(8))
   ```

3. **CPU-Based Configuration**:
   ```go
   // Creates scanner with worker count matching CPU cores
   scanner := scanner.New(scanner.WithWorkers(runtime.NumCPU()))
   ```

### Worker Performance Guidelines

1. **Small Files** (< 10KB):
   - Single worker is sufficient
   - Overhead of multiple workers not beneficial
   ```go
   scanner := scanner.New(scanner.WithWorkers(1))
   ```

2. **Medium Files** (10KB - 1MB):
   - 4-8 workers typically optimal
   - Balance between parallelism and overhead
   ```go
   scanner := scanner.New(scanner.WithWorkers(4))
   ```

3. **Large Files** (> 1MB):
   - Worker count can match or exceed CPU cores
   - Benefits from increased parallelism
   ```go
   // For large file processing
   scanner := scanner.New(scanner.WithWorkers(runtime.NumCPU() * 2))
   ```

### Example: Worker Configuration

```go
package main

import (
    "context"
    "runtime"
    "github.com/stackloklabs/secret-scanning-ai/scanner"
)

func main() {
    // Create scanner with CPU-optimized workers
    s := scanner.New(scanner.WithWorkers(runtime.NumCPU()))

    // Create context with timeout
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    // Process large file
    results, err := s.Scan(ctx, largeText)
    if err != nil {
        panic(err)
    }

    // Results are automatically merged from all workers
    for _, result := range results {
        // Process results...
    }
}
```

### Benchmark Results with Different Worker Counts

```
BenchmarkScanner/small/1_workers    ~54ns/op    0 B/op    0 allocs/op
BenchmarkScanner/small/4_workers    ~54ns/op    0 B/op    0 allocs/op
BenchmarkScanner/small/8_workers    ~56ns/op    0 B/op    0 allocs/op
BenchmarkScanner/small/16_workers   ~54ns/op    0 B/op    0 allocs/op

BenchmarkScanner/medium/1_workers   ~3.3µs/op   2 B/op    0 allocs/op
BenchmarkScanner/medium/4_workers   ~3.3µs/op   2 B/op    0 allocs/op
BenchmarkScanner/medium/8_workers   ~3.3µs/op   3 B/op    0 allocs/op
BenchmarkScanner/medium/16_workers  ~3.4µs/op   3 B/op    0 allocs/op

BenchmarkScanner/large/1_workers    ~35µs/op    366 B/op  0 allocs/op
BenchmarkScanner/large/4_workers    ~34µs/op    371 B/op  0 allocs/op
BenchmarkScanner/large/8_workers    ~35µs/op    377 B/op  0 allocs/op
BenchmarkScanner/large/16_workers   ~34µs/op    423 B/op  0 allocs/op
```

4. **Streaming Operations**:
   ```go
   func (s *Scanner) StreamScan(ctx context.Context, reader io.Reader) (<-chan Result, error) {
       resultsChan := make(chan Result)
       go func() {
           defer close(resultsChan)
           scanner := bufio.NewScanner(reader)
           for scanner.Scan() {
               select {
               case <-ctx.Done():
                   return
               default:
                   // Process line and send results
               }
           }
       }()
       return resultsChan, nil
   }
   ```

This multi-level context awareness ensures:
- Immediate response to cancellation requests
- Proper resource cleanup
- Prevention of goroutine leaks
- Coordinated cancellation of related operations

## Performance

The scanner is optimized for high performance across different workloads:

### Parallel Processing
- Small files (~1KB): ~54ns per operation
- Medium files (~100KB): ~3.3µs per operation
- Large files (~1MB): ~34µs per operation
- Configurable worker pool (default: 4 workers)
- Near-zero memory allocations for cached results

### Memory Efficiency
- Parallel processing: 0-423 bytes/op
- Streaming mode for handling large files
- Efficient memory usage through chunked processing

### Caching
- Cached lookups: ~3.3µs/op with zero allocations
- Thread-safe cache implementation
- Automatic caching of frequently scanned content

## Installation

```bash
go get github.com/stackloklabs/secret-scanning-api
```

## Usage

### As a Library

```go
package main

import (
    "context"
    "fmt"
    "github.com/stackloklabs/secret-scanning-api/scanner"
    "github.com/stackloklabs/secret-scanning-api/patterns"
)

func main() {
    // Initialize scanner with custom worker count
    s := scanner.New(scanner.WithWorkers(8))

    // Add default patterns
    for name, pattern := range patterns.GetAllPatterns() {
        s.AddPattern(name, pattern)
    }

    // Create context with timeout
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    // Scan text
    text := "config.password = 'MySecretPass123!'"
    results, err := s.Scan(ctx, text)
    if err != nil {
        panic(err)
    }

    // Process results
    for _, result := range results {
        fmt.Printf("Found %s: %s (Confidence: %.2f)\n",
            result.Type,
            result.Value,
            result.Confidence)
    }
}
```

### Command Line Usage

```bash
# Scan a file
secret-scanner -file config.json

# Scan text directly
secret-scanner -text "api_key=1234567890abcdef"

# Scan from stdin
cat config.json | secret-scanner

# Use only entropy-based detection
secret-scanner -entropy-only -file config.json
```

## Contributing

Contributions are welcome! Areas for improvement:

1. Additional secret patterns
2. Performance optimizations
3. Integration examples
4. Documentation improvements

## License

Apache 2.0

