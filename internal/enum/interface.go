package enum

import "context"

type Enumerator interface {
	Enumerate(ctx context.Context, domain string) (<-chan string, error)
	Name() string
}
