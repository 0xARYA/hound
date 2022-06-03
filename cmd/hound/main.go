package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/acme"
	"src.agwa.name/go-listener"
	"src.agwa.name/go-listener/cert"

	net "github.com/0xARYA/hound/internal/net"
	TLS "github.com/0xARYA/hound/pkg/TLS"
)

// temporary, i promise.
func handler(w http.ResponseWriter, req *http.Request) {
	rawClientHello := req.Context().Value(net.HandshakeKey).([]byte)

	clientHello := TLS.UnmarshalClientHello(rawClientHello)

	TLSFingerprint := TLS.Fingerprint(clientHello)

	w.Write([]byte(TLSFingerprint))
}

func main() {
	certificatePath := flag.String("certificatePath", "certificates/localhost.pem", "Server Certificate Path")
	listenerInterface := flag.String("listenerInterface", "tcp:443", "Server Listener Interface")

	flag.Parse()

	if *certificatePath == "" {
		log.Fatal("No certificate path provided")
	}

	TLSConfiguration := tls.Config{
		NextProtos:             []string{"h2", "http/1.1", acme.ALPNProto},
		SessionTicketsDisabled: true,
		GetCertificate:         cert.GetCertificateFromFile(*certificatePath),
	}

	// again. temporary, i promise - still need to implement other fingerprinting methods.
	router := mux.NewRouter()
	router.HandleFunc("/", handler)

	httpServer := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  5 * time.Second,
		Handler:      router,
		ConnContext:  net.HandshakeConnectionContext,
	}

	streamListener, streamListenerError := listener.Open(*listenerInterface)

	if streamListenerError != nil {
		log.Fatal(streamListenerError)
	}

	defer streamListener.Close()

	handshakeListener := net.NewHandshakeListener(streamListener)

	TLSListener := tls.NewListener(handshakeListener, &TLSConfiguration)

	log.Fatal(httpServer.Serve(TLSListener))
}
