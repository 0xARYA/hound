package houndHTTP

import (
	"bufio"
	"bytes/tls"
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
		log.Println("Failed to retrieve client hello")

		return
	}

	connectionTLSFingerprint := houndTLS.Fingerprint(connectionClientHello)

	connectionReader := bufio.NewReader(connection)

	preface, connectionPeekError := connectionReader.Peek(HTTP2PrefaceByteLength)

	if connectionPeekError != nil {
		log.Println(connectionPeekError)

		return
	}

	

	if bytes.Equal(preface, HTTP2PrefaceBytes) {
		handleHTTP2(connection, connectionTLSFingerprint)
	}
}
