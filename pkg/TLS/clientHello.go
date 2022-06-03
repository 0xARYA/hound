package TLS

import (
	"golang.org/x/crypto/cryptobyte"
)

type ProtocolVersion uint16

func (v ProtocolVersion) Hi() uint8 {
	return uint8(v >> 8)
}

func (v ProtocolVersion) Lo() uint8 {
	return uint8(v)
}

type CompressionMethod uint8

type ClientHello struct {
	Raw []byte `json:"raw"`

	Version            ProtocolVersion     `json:"version"`
	Random             []byte              `json:"random"`
	SessionID          []byte              `json:"sessionID"`
	CipherSuites       []CipherSuite       `json:"cipherSuites"`
	CompressionMethods []CompressionMethod `json:"compressionMethods"`
	Extensions         []Extension         `json:"extensions"`

	Extra struct {
		ServerName   *string  `json:"serverName"`
		ProvidedSCTs bool     `json:"providedSCTs"`
		Protocols    []string `json:"protocols"`
	} `json:"extra"`
}

func UnmarshalClientHello(handshake []byte) *ClientHello {
	clientHello := &ClientHello{Raw: handshake}

	handshakeMessage := cryptobyte.String(handshake)

	var handshakeMessageType uint8
	if !handshakeMessage.ReadUint8(&handshakeMessageType) || handshakeMessageType != 1 {
		return nil
	}

	var rawClientHello cryptobyte.String

	if !handshakeMessage.ReadUint24LengthPrefixed(&rawClientHello) || !handshakeMessage.Empty() {
		return nil
	}

	if !rawClientHello.ReadUint16((*uint16)(&clientHello.Version)) {
		return nil
	}

	if !rawClientHello.ReadBytes(&clientHello.Random, 32) {
		return nil
	}

	if !rawClientHello.ReadUint8LengthPrefixed((*cryptobyte.String)(&clientHello.SessionID)) {
		return nil
	}

	var cipherSuites cryptobyte.String

	if !rawClientHello.ReadUint16LengthPrefixed(&cipherSuites) {
		return nil
	}

	clientHello.CipherSuites = []CipherSuite{}

	for !cipherSuites.Empty() {
		var cipherSuite uint16

		if !cipherSuites.ReadUint16(&cipherSuite) {
			return nil
		}

		clientHello.CipherSuites = append(clientHello.CipherSuites, MakeCipherSuite(cipherSuite))
	}

	var compressionMethods cryptobyte.String

	if !rawClientHello.ReadUint8LengthPrefixed(&compressionMethods) {
		return nil
	}

	clientHello.CompressionMethods = []CompressionMethod{}
	for !compressionMethods.Empty() {
		var compressionMethod uint8

		if !compressionMethods.ReadUint8(&compressionMethod) {
			return nil
		}

		clientHello.CompressionMethods = append(clientHello.CompressionMethods, CompressionMethod(compressionMethod))
	}

	clientHello.Extensions = []Extension{}

	if rawClientHello.Empty() {
		return clientHello
	}

	var extensions cryptobyte.String
	if !rawClientHello.ReadUint16LengthPrefixed(&extensions) {
		return nil
	}

	for !extensions.Empty() {
		var extensionType uint16
		var extensionData cryptobyte.String

		if !extensions.ReadUint16(&extensionType) || !extensions.ReadUint16LengthPrefixed(&extensionData) {
			return nil
		}

		parseExtensionData := extensionParsers[extensionType]
		if parseExtensionData == nil {
			parseExtensionData = ParseUnknownExtensionData
		}

		parsedExtensionData := parseExtensionData(extensionData)

		clientHello.Extensions = append(clientHello.Extensions, Extension{
			Type:    extensionType,
			Name:    Extensions[extensionType].Name,
			Grease:  Extensions[extensionType].Grease,
			Private: Extensions[extensionType].Private,
			Data:    parsedExtensionData,
		})

		switch extensionType {
		case 0:
			clientHello.Extra.ServerName = &parsedExtensionData.(*ServerNameData).HostName
		case 16:
			clientHello.Extra.Protocols = parsedExtensionData.(*ALPNData).Protocols
		case 18:
			clientHello.Extra.ProvidedSCTs = true
		}

	}

	if !rawClientHello.Empty() {
		return nil
	}

	return clientHello
}
