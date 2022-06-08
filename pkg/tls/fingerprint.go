package houndTLS

import (
	"fmt"
	"strconv"

	"crypto/tls"

	houndNet "github.com/0xARYA/hound/internal/net"
)

type TLSFingerprint struct {
	Client string
	Server string
}

func parseClientHello(clientHello *ClientHello) string {
	var (
		ciphers         string
		extensions      string
		supportedGroups string
		pointFormats    string
	)

	for _, cipher := range clientHello.CipherSuites {
		if !cipher.Grease {
			if len(ciphers) > 0 {
				ciphers += "-"
			}

			ciphers += strconv.FormatUint(uint64(cipher.CodeUint16()), 10)
		}
	}

	for _, extension := range clientHello.Extensions {
		if !extension.Grease {
			if len(extensions) > 0 {
				extensions += "-"
			}

			extensions += strconv.FormatUint(uint64(extension.Type), 10)
		}

		if extension.Type == 10 {
			supportedGroupsData := extension.Data.(*SupportedGroupsData)

			for _, supportedGroup := range supportedGroupsData.Groups {
				if (supportedGroup & 0x0F0F) != 0x0A0A {
					if len(supportedGroups) > 0 {
						supportedGroups += "-"
					}

					supportedGroups += strconv.FormatUint(uint64(supportedGroup), 10)
				}
			}
		}

		if extension.Type == 11 {
			pointFormatsData := extension.Data.(*ECPointFormatsData)

			for _, pointFormat := range pointFormatsData.Formats {
				if len(pointFormats) > 0 {
					pointFormats += "-"
				}

				pointFormats += strconv.FormatUint(uint64(pointFormat), 10)
			}
		}
	}

	return fmt.Sprintf("%d,%s,%s,%s,%s", clientHello.Version, ciphers, extensions, supportedGroups, pointFormats)
}

func parseServerHello(connectionState tls.ConnectionState) string {
	var (
		version string
		cipher  string
	)

	version = strconv.Itoa(int(connectionState.Version))

	if !Extensions[connectionState.CipherSuite].Grease {
		cipher = strconv.Itoa(int(connectionState.CipherSuite))
	}

	return fmt.Sprintf("%s,%s", version, cipher)
}

func Fingerprint(connection *tls.Conn) *TLSFingerprint {
	handshakeConnection, handshakeConnectionOK := connection.NetConn().(*houndNet.HandshakeConnection)

	if !handshakeConnectionOK {
		return nil
	}

	clientHello := UnmarshalClientHello(handshakeConnection.Handshake)

	clientFingerprint := parseClientHello(clientHello)
	serverFingerprint := parseServerHello(connection.ConnectionState())

	return &TLSFingerprint{
		Client: clientFingerprint,
		Server: serverFingerprint,
	}
}
