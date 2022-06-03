package TLS

import (
	"golang.org/x/crypto/cryptobyte"
)

type ExtensionData interface{}

type Extension struct {
	Type    uint16        `json:"type"`
	Name    string        `json:"name,omitempty"`
	Grease  bool          `json:"grease,omitempty"`
	Private bool          `json:"private,omitempty"`
	Data    ExtensionData `json:"data"`
}

type UnknownExtensionData struct {
	Raw []byte `json:"raw"`
}

func ParseUnknownExtensionData(data []byte) ExtensionData {
	return &UnknownExtensionData{
		Raw: data,
	}
}

type EmptyExtensionData struct {
	Raw   []byte `json:"raw"`
	Valid bool   `json:"valid"`
}

func ParseEmptyExtensionData(data []byte) ExtensionData {
	return &EmptyExtensionData{
		Raw:   data,
		Valid: len(data) == 0,
	}
}

// server_name - RFC 6066, Section 3
type ServerNameData struct {
	Raw      []byte `json:"raw"`
	Valid    bool   `json:"valid"`
	HostName string `json:"hostName"`
}

func ParseServerNameData(raw []byte) ExtensionData {
	SNIData := &ServerNameData{Raw: raw}
	extensionData := cryptobyte.String(raw)

	var nameList cryptobyte.String

	if !extensionData.ReadUint16LengthPrefixed(&nameList) || nameList.Empty() {
		return SNIData
	}

	for !nameList.Empty() {
		var nameType uint8

		if !nameList.ReadUint8(&nameType) {
			return SNIData
		}

		var nameData cryptobyte.String

		if !nameList.ReadUint16LengthPrefixed(&nameData) || nameData.Empty() {
			return SNIData
		}

		switch nameType {
		case 0:
			if SNIData.HostName != "" {
				return SNIData
			}

			SNIData.HostName = string(nameData)
		}
	}

	if !extensionData.Empty() {
		return SNIData
	}

	SNIData.Valid = true

	return SNIData
}

type ALPNData struct {
	Raw       []byte   `json:"raw"`
	Valid     bool     `json:"valid"`
	Protocols []string `json:"protocols"`
}

func ParseALPNData(raw []byte) ExtensionData {
	ALPNData := &ALPNData{Raw: raw, Protocols: []string{}}
	extensionData := cryptobyte.String(raw)

	var protocolNameList cryptobyte.String

	if !extensionData.ReadUint16LengthPrefixed(&protocolNameList) || protocolNameList.Empty() {
		return ALPNData
	}

	for !protocolNameList.Empty() {
		var protocolName cryptobyte.String

		if !protocolNameList.ReadUint8LengthPrefixed(&protocolName) || protocolName.Empty() {
			return ALPNData
		}

		ALPNData.Protocols = append(ALPNData.Protocols, string(protocolName))
	}

	if !extensionData.Empty() {
		return ALPNData
	}

	ALPNData.Valid = true

	return ALPNData
}

// RFC 8422
type SupportedGroupsData struct {
	Raw    []byte   `json:"raw"`
	Valid  bool     `json:"valid"`
	Groups []uint16 `json:"groups"`
}

func ParseSupportedGroupsData(rawData []byte) ExtensionData {
	parsedSupportedGroupsData := &SupportedGroupsData{Raw: rawData, Groups: []uint16{}}

	supportedGroupsData := cryptobyte.String(rawData)

	var supportedGroupsList cryptobyte.String

	if !supportedGroupsData.ReadUint16LengthPrefixed(&supportedGroupsList) || supportedGroupsList.Empty() {
		return parsedSupportedGroupsData
	}

	for !supportedGroupsList.Empty() {
		var supportedGroupCode uint16

		if !supportedGroupsList.ReadUint16(&supportedGroupCode) {
			return parsedSupportedGroupsData
		}

		parsedSupportedGroupsData.Groups = append(parsedSupportedGroupsData.Groups, supportedGroupCode)
	}

	if !supportedGroupsData.Empty() {
		return parsedSupportedGroupsData
	}

	parsedSupportedGroupsData.Valid = true

	return parsedSupportedGroupsData
}

// RFC 8422
type ECPointFormatsData struct {
	Raw     []byte   `json:"raw"`
	Valid   bool     `json:"valid"`
	Formats []uint16 `json:"formats"`
}

func ParseECPointFormatsData(rawData []byte) ExtensionData {
	parsedPointFormatsData := &ECPointFormatsData{Raw: rawData, Formats: []uint16{}}
	pointFormatsData := cryptobyte.String(rawData)

	var pointFormatsList cryptobyte.String

	if !pointFormatsData.ReadUint8LengthPrefixed(&pointFormatsList) || pointFormatsList.Empty() {
		return parsedPointFormatsData
	}

	for !pointFormatsList.Empty() {
		var pointFormatCode uint8

		if !pointFormatsList.ReadUint8(&pointFormatCode) {
			return parsedPointFormatsData
		}

		parsedPointFormatsData.Formats = append(parsedPointFormatsData.Formats, uint16(pointFormatCode))
	}

	if !pointFormatsData.Empty() {
		return parsedPointFormatsData
	}

	parsedPointFormatsData.Valid = true

	return parsedPointFormatsData
}

var extensionParsers = map[uint16]func([]byte) ExtensionData{
	0:  ParseServerNameData,
	10: ParseSupportedGroupsData,
	11: ParseECPointFormatsData,
	16: ParseALPNData,
	18: ParseEmptyExtensionData,
	22: ParseEmptyExtensionData,
	23: ParseEmptyExtensionData,
	49: ParseEmptyExtensionData,
}
