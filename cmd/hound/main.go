package main

import (
	"crypto/tls"
	"flag"
	"log"

	"golang.org/x/crypto/acme"
	"src.agwa.name/go-listener"
	"src.agwa.name/go-listener/cert"

	houndHTTP "github.com/0xARYA/hound/internal/http"
	houndNet "github.com/0xARYA/hound/internal/net"
)

func main() {
	certificatePath := flag.String("certificatePath", "certificates/localhost.pem", "Server Certificate Path")
	listenerInterface := flag.String("listenerInterface", "tcp:443", "Server Listener Interface")

	flag.Parse()

	if *certificatePath == "" {
		log.Fatal("No Certificate Path Specified.")
	}

	tlsConfiguration := tls.Config{
		NextProtos:             []string{"h2", "http/1.1", acme.ALPNProto},
		SessionTicketsDisabled: true,
		GetCertificate:         cert.GetCertificateFromFile(*certificatePath),
	}

	streamListener, listenerOpenError := listener.Open(*listenerInterface)

	if listenerOpenError != nil {
		log.Fatal(listenerOpenError)
	}

	handshakeListener := houndNet.NewHandshakeListener(streamListener)

	tlsListener := tls.NewListener(handshakeListener, &tlsConfiguration)

	defer tlsListener.Close()

	log.Println("Server Running On: ", tlsListener.Addr().String())

	for {
		connection, connectionAcceptError := tlsListener.Accept()

		if connectionAcceptError != nil {
			log.Println("Failed To Accept Connection: ", connectionAcceptError)

			continue
		}

		go houndHTTP.HandleConnection(connection)
	}
}
