package net

import (
	"bytes"
	"io"
	"net"
)

type HandshakeConnection struct {
	net.Conn
	Handshake []byte

	reader io.Reader
}

func (connection *HandshakeConnection) Read(p []byte) (int, error) {
	return connection.reader.Read(p)
}

func NewHandshakeConnection(connection net.Conn) (*HandshakeConnection, error) {
	handshakeBytes := new(bytes.Buffer)

	connectionReader := io.TeeReader(connection, handshakeBytes)

	handshake, handshakeReadError := NewHandshakeReader(connectionReader).ReadMessage()

	if handshakeReadError != nil {
		return nil, handshakeReadError
	}

	return &HandshakeConnection{
		Conn:      connection,
		Handshake: handshake,

		reader: io.MultiReader(handshakeBytes, connection),
	}, nil
}
