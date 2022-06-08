package houndTLS

import (
	"embed"
	"encoding/json"
	"log"
	"strconv"
)

//go:embed static/extensions.json static/cipherSuites.json
var staticFS embed.FS

type StaticExtension struct {
	Name      string `json:"name,omitempty"`
	Reserved  bool   `json:"reserved,omitempty"`
	Grease    bool   `json:"grease,omitempty"`
	Private   bool   `json:"private,omitempty"`
	Reference string `json:"reference,omitempty"`
}

type StaticCipherSuite struct {
	Name   string `json:"name,omitempty"`
	Grease bool   `json:"grease,omitempty"`
}

var Extensions = loadStaticFile[StaticExtension]("static/extensions.json")

var CipherSuites = loadStaticFile[StaticCipherSuite]("static/cipherSuites.json")

func loadStaticFile[Type interface{}](filePath string) map[uint16]Type {
	JSONFile, JSONFileError := staticFS.ReadFile(filePath)

	if JSONFileError != nil {
		log.Fatal(JSONFileError)
	}

	var data map[string]Type

	JSONUnmarshalError := json.Unmarshal(JSONFile, &data)

	if JSONUnmarshalError != nil {
		log.Fatal(JSONUnmarshalError)
	}

	var parsed = make(map[uint16]Type)

	for key, value := range data {
		index, _ := strconv.ParseUint(key, 10, 16)

		parsed[uint16(index)] = value
	}

	return parsed
}
