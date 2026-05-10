package output

import (
	"encoding/json"
	"os"

	"github.com/AliMousaviSoft/subjackal/internal/model"
)

type JSONWriter struct {
	file    *os.File
	encoder *json.Encoder
}

func NewJSONWriter(path string) (*JSONWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return &JSONWriter{file: f, encoder: enc}, nil
}

func (w *JSONWriter) Write(sub *model.Subdomain) error {
	return w.encoder.Encode(sub)
}

func (w *JSONWriter) Close() error {
	return w.file.Close()
}
