//go:build generate

//go:generate go run tools/generate/cipherSuites.go

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

type StaticCipherSuite struct {
	Name   string `json:"name,omitempty"`
	Grease bool   `json:"grease,omitempty"`
}

const sourceURL = `https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv`

const outputFilePath = "pkg/TLS/static/cipherSuites.json"

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

	cipherSuites := make(map[uint16]StaticCipherSuite)

	for {
		row, rowReadError := reader.Read()

		if rowReadError == io.EOF {
			break
		} else if rowReadError != nil {
			log.Fatal(rowReadError)
		}

		var (
			value       = row[0]
			description = row[1]
			reference   = row[4]
		)

		if description == "Unassigned" {
			continue
		}

		if strings.Contains(description, "Reserved") && reference != "[RFC8701]" {
			continue
		}

		valueFields := strings.Split(value, ",")

		hi, hiParseError := strconv.ParseUint(valueFields[0], 0, 8)

		if hiParseError != nil {
			log.Fatal(hiParseError)
		}

		lo, loParseError := strconv.ParseUint(valueFields[1], 0, 8)

		if loParseError != nil {
			log.Fatal(loParseError)
		}

		code := (uint16(hi) << 8) | uint16(lo)

		if strings.Contains(description, "Reserved") && reference == "[RFC8701]" {
			cipherSuites[code] = StaticCipherSuite{Grease: true}
		} else {
			cipherSuites[code] = StaticCipherSuite{Name: description}
		}
	}

	cipherSuitesJSON, cipherSuitesJSONError := json.Marshal(cipherSuites)

	if cipherSuitesJSONError != nil {
		log.Fatal(cipherSuitesJSONError)
	}

	writeFileError := os.WriteFile(outputFilePath, cipherSuitesJSON, 0666)

	if writeFileError != nil {
		log.Fatal(responseError)
	}
}
