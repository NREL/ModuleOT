package main

import (
	"net"

	"moduleot/internal/socketfunctions"
)

func main() {
	servererrc := make(chan error)
	CERTFILE := "/usr/lib/ssl/certs/certificate.pem"
	KEYFILE := "/usr/lib/ssl/certs/key.key"

	// Start OpenSSL Server
	ServerInst := socketfunctions.ServerInstance{}
	ServerInst.IP = "127.0.0.1"
	ServerInst.PORT = "8000"
	ServerInst.WHITELIST = []string{"127.0.0.1"}
	ServerInst.ClientConnections = make(map[string]net.Conn)
	ServerTLSRx := make(chan socketfunctions.TLSPacket, 5)
	ServerTLSTx := make(chan socketfunctions.TLSPacket, 5)
	go ServerInst.SpawnOpenSSLServer(CERTFILE, KEYFILE, ServerTLSRx, ServerTLSTx, "tcp", servererrc)

}
