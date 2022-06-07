package houndHTTP

import (
	"bytes"
	"crypto/tls"
	"log"
	"net"

	houndNet "github.com/0xARYA/hound/internal/net"
	houndTLS "github.com/0xARYA/hound/pkg/TLS"
)

var HTTP2PrefaceBytes = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

var HTTP2PrefaceByteLength = len(HTTP2PrefaceBytes)

func getConnectionClientHello(connection net.Conn) *houndTLS.ClientHello {
	TLSConnection, OK := connection.(*tls.Conn)

	if !OK {
		return nil
	}

	handshakeConnection, OK := TLSConnection.NetConn().(*houndNet.HandshakeConnection)

	if !OK {
		return nil
	}

	return houndTLS.UnmarshalClientHello(handshakeConnection.Handshake)

}

func HandleConnection(connection net.Conn) {
	defer connection.Close()

	connectionClientHello := getConnectionClientHello(connection)

	if connectionClientHello == nil {
		log.Println("Failed To Retrieve Client Hello")

		return
	}

	connectionTLSFingerprint := houndTLS.Fingerprint(connectionClientHello)

	connectionPreface := make([]byte, HTTP2PrefaceByteLength)

	_, connectionReadError := connection.Read(connectionPreface)

	if connectionReadError != nil {
		log.Println(connectionReadError)

		return
	}

	if bytes.Equal(connectionPreface, HTTP2PrefaceBytes) {
		handleHTTP2(connection, connectionTLSFingerprint)
	}
}
