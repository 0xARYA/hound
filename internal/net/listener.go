package net

import (
	"net"
)

type HandshakeListener struct {
	net.Listener
}

func (listener *HandshakeListener) Accept() (net.Conn, error) {
	connection, connectionAcceptError := listener.Listener.Accept()

	if connectionAcceptError != nil {
		return nil, connectionAcceptError
	}

	return NewHandshakeConnection(connection)
}

func NewHandshakeListener(instance net.Listener) net.Listener {
	return &HandshakeListener{Listener: instance}
}
