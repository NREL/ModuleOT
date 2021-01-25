package main

import "socketfunctions"

func main() {
	networkChan := make(chan socketfunctions.TLSPacket, 5)
	clienterrc := make(chan socketfunctions.OpenSSLClientData)
	CERTFILE := "/usr/lib/ssl/certs/certificate.pem"
	KEYFILE := "/usr/lib/ssl/certs/key.key"
	TLSRx := make(chan socketfunctions.TLSPacket, 5)
	TLSTx := make(chan socketfunctions.TLSPacket, 5)
	closeChan := make(chan bool)
	socketfunctions.ConnectOpenSSLClient(CERTFILE, KEYFILE, TLSRx, TLSTx, "tcp", "127.0.0.1", "8000", networkChan, clienterrc, closeChan)
}
