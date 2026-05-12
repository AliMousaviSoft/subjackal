package enum

import (
	"bufio"
	"context"
	"io"
	"strings"
)

type ReaderEnum struct {
	reader io.Reader
}

func NewReaderEnum(r io.Reader) *ReaderEnum {
	return &ReaderEnum{reader: r}
}

func (r *ReaderEnum) Name() string { return "stdin" }

func (r *ReaderEnum) Enumerate(ctx context.Context, domain string) (<-chan string, error) {
	out := make(chan string, 100)
	go func() {
		defer close(out)
		seen := make(map[string]bool)
		scanner := bufio.NewScanner(r.reader)
		for scanner.Scan() {
			line := strings.ToLower(strings.TrimSpace(scanner.Text()))
			if line == "" || strings.HasPrefix(line, "#") || seen[line] {
				continue
			}
			seen[line] = true
			select {
			case <-ctx.Done():
				return
			case out <- line:
			}
		}
	}()
	return out, nil
}