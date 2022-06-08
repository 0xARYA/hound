package houndHTTP

import (
	"bytes"
	"crypto/tls"
	"log"
	"net"

	houndTLS "github.com/0xARYA/hound/pkg/tls"
)

var HTTP2PrefaceBytes = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

var HTTP2PrefaceByteLength = len(HTTP2PrefaceBytes)

func HandleConnection(connection net.Conn) {
	defer connection.Close()

	connectionPreface := make([]byte, HTTP2PrefaceByteLength)

	_, connectionReadError := connection.Read(connectionPreface)

	if connectionReadError != nil {
		log.Println(connectionReadError)

		return
	}

	tlsConnection, tlsConnectionOK := connection.(*tls.Conn)

	if !tlsConnectionOK {
		log.Println("Failed To Cast Connection To TLS Connection { *tls.Conn }.")

		return
	}

	tlsFingerprint := houndTLS.Fingerprint(tlsConnection)

	if tlsFingerprint == nil {
		log.Println("Failed To [Retrieve] Fingerprint TLS Connection.")
	}

	if bytes.Equal(connectionPreface, HTTP2PrefaceBytes) {
		handleHTTP2(connection, tlsFingerprint)
	} else {
		// TODO: Handle HTTP/1
	}
}
