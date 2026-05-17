package services

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/unidoc/unioffice/document"
)

type DOCXService struct{}

func NewDOCXService() *DOCXService {
	return &DOCXService{}
}

func (s *DOCXService) ExtractTextFromReader(r io.Reader) (string, error) {
	buf := new(bytes.Buffer)
	_, err := io.Copy(buf, r)
	if err != nil {
		return "", fmt.Errorf("read docx: %w", err)
	}

	data := buf.Bytes()
	doc, err := document.Read(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", fmt.Errorf("parse docx: %w", err)
	}
	defer doc.Close()

	var textBuilder strings.Builder

	paragraphs := doc.Paragraphs()
	for i, para := range paragraphs {
		runs := para.Runs()
		for _, run := range runs {
			textBuilder.WriteString(run.Text())
		}

		if i < len(paragraphs)-1 {
			textBuilder.WriteString("\n")
		}
	}

	text := strings.TrimSpace(textBuilder.String())
	if text == "" {
		return "", fmt.Errorf("document contains no text")
	}

	return text, nil
}
