//go:build generate

//go:generate go run tools/generate/extensions.go

package main

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type StaticExtension struct {
	Name      string `json:"name,omitempty"`
	Reserved  bool   `json:"reserved,omitempty"`
	Grease    bool   `json:"grease,omitempty"`
	Private   bool   `json:"private,omitempty"`
	Reference string `json:"reference,omitempty"`
}

const sourceURL = `https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values-1.csv`

const outputFilePath = "pkg/tls/static/extensions.json"

func main() {
	client := &http.Client{Timeout: 1 * time.Minute}

	response, responseError := client.Get(sourceURL)

	if responseError != nil {
		log.Fatal(responseError)
	}

	defer response.Body.Close()

	if response.StatusCode != 200 {
		log.Fatalf("%s: %d %s", sourceURL, response.StatusCode, response.Status)
	}

	reader := csv.NewReader(response.Body)

	// Discard header
	_, readerError := reader.Read()

	if readerError != nil {
		log.Fatal(readerError)
	}

	extensions := make(map[uint16]StaticExtension)

	for {
		row, rowReadError := reader.Read()

		if rowReadError == io.EOF {
			break
		} else if rowReadError != nil {
			log.Fatal(rowReadError)
		}

		var (
			valueString = row[0]
			name        = row[1]
			reference   = row[5]
		)

		if name == "Unassigned" {
			continue
		}

		if index := strings.Index(name, " (renamed from"); index != -1 {
			name = name[:index]
		}

		var (
			firstValue           uint64
			firstValueParseError error

			lastValue           uint64
			lastValueParseError error
		)

		valueFields := strings.SplitN(valueString, "-", 2)

		if len(valueFields) == 2 {
			firstValue, firstValueParseError = strconv.ParseUint(valueFields[0], 0, 16)

			if firstValueParseError != nil {
				log.Fatal(firstValueParseError)
			}

			lastValue, lastValueParseError = strconv.ParseUint(valueFields[1], 0, 16)

			if lastValueParseError != nil {
				log.Fatal(lastValueParseError)
			}
		} else {
			firstValue, firstValueParseError = strconv.ParseUint(valueString, 0, 16)

			if lastValueParseError != nil {
				log.Fatal(rowReadError)
			}

			lastValue = firstValue
		}

		var extension StaticExtension

		if name == "Reserved" && reference == "[RFC8701]" {
			extension.Reserved = true
			extension.Grease = true
		} else if name == "Reserved for Private Use" {
			extension.Reserved = true
			extension.Private = true
		} else if name == "Reserved" {
			extension.Reserved = true
		} else {
			extension.Name = name
		}

		extension.Reference = reference

		for value := firstValue; value <= lastValue; value++ {
			extensions[uint16(value)] = extension
		}
	}

	extensionsJSON, extensionsJSONError := json.Marshal(extensions)

	if extensionsJSONError != nil {
		log.Fatal(extensionsJSONError)
	}

	writeFileError := os.WriteFile(outputFilePath, extensionsJSON, 0666)

	if writeFileError != nil {
		log.Fatal(writeFileError)
	}
}
