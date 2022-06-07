package houndTLS

import (
	"fmt"
	"strconv"
)

func Fingerprint(clientHello *ClientHello) string {
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
