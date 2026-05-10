package enum

import (
	"bufio"
	"context"
	"os"
	"strings"
)

type FileEnum struct {
	path string
}

func NewFileEnum(path string) *FileEnum {
	return &FileEnum{path: path}
}

func (f *FileEnum) Name() string { return "file" }

func (f *FileEnum) Enumerate(ctx context.Context, domain string) (<-chan string, error) {
	out := make(chan string, 100)

	file, err := os.Open(f.path)
	if err != nil {
		close(out)
		return out, err
	}

	go func() {
		defer close(out)
		defer file.Close()

		seen := make(map[string]bool)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.ToLower(strings.TrimSpace(scanner.Text()))
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if seen[line] {
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