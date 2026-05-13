package services

import (
	"fmt"
	"io"
	"strings"

	"github.com/ledongthuc/pdf"
)

type PDFService struct{}

func NewPDFService() *PDFService {
	return &PDFService{}
}

func (s *PDFService) ExtractText(pdfData []byte) (string, error) {
	reader, err := pdf.NewReader(strings.NewReader(string(pdfData)), int64(len(pdfData)))
	if err != nil {
		return "", fmt.Errorf("failed to read PDF: %w", err)
	}

	var textBuilder strings.Builder

	pageCount := reader.NumPage()
	for pageNum := 1; pageNum <= pageCount; pageNum++ {
		page := reader.Page(pageNum)
		if page.V.IsNull() {
			continue
		}

		text, err := page.GetPlainText(nil)
		if err != nil {
			return "", fmt.Errorf("failed to extract text from page %d: %w", pageNum, err)
		}

		if strings.TrimSpace(text) != "" {
			textBuilder.WriteString(fmt.Sprintf("\n--- Page %d ---\n", pageNum))
			textBuilder.WriteString(text)
		}
	}

	if textBuilder.Len() == 0 {
		return "", fmt.Errorf("no text found in PDF")
	}

	return textBuilder.String(), nil
}

func (s *PDFService) ExtractTextFromReader(reader io.Reader) (string, error) {
	pdfData, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("failed to read PDF data: %w", err)
	}

	return s.ExtractText(pdfData)
}
