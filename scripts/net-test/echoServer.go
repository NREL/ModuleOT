package main

import (
	"encoding/binary"
	"fmt"
	"net"
)

// only needed below for sample processing

func main() {

	fmt.Println("Launching Echo server...")

	// listen on all interfaces port 80
	ln, _ := net.Listen("tcp", ":8080")

	// accept connection on port
	conn, _ := ln.Accept()
	for {
		buf := make([]byte, 1024)
		nbyte, _ := conn.Read(buf)
		conn.Write(buf[:nbyte])
		message := int64(binary.BigEndian.Uint64(buf[:nbyte]))
		fmt.Println("Echo Time Received:", message)
	}
}
