package net

import (
	"context"
	"crypto/tls"
	"net"
)

type contextKeyType int

var HandshakeKey = contextKeyType(0)

func HandshakeConnectionContext(ctx context.Context, connection net.Conn) context.Context {
	TLSConnection, OK := connection.(*tls.Conn)

	if !OK {
		return ctx
	}

	TLSHandshakeConnection, OK := TLSConnection.NetConn().(*HandshakeConnection)

	if !OK {
		return ctx
	}

	return context.WithValue(ctx, HandshakeKey, TLSHandshakeConnection.Handshake)
}
