package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

func main() {

	// Check for command-line flags
	logfileFlag := flag.String("IP", "127.0.0.1", "Server IP to dial (default:127.0.0.1)")
	flag.Parse()

	fmt.Println("Writing output to latencyMeasurements.txt")
	f, _ := os.Create("latencyMeasurements.txt")
	// connect to this socket
	fmt.Println("Launching Latency measurement client")
	conn, _ := net.Dial("tcp", *logfileFlag+":8080")
	count := 0
	for {
		// read in input from stdin
		timeStart := uint64(time.Now().UnixNano())
		bytes := make([]byte, 8)
		binary.BigEndian.PutUint64(bytes, timeStart)
		conn.Write(bytes)

		// listen for reply
		buf := make([]byte, 1024)
		nbyte, _ := conn.Read(buf)
		latency := (time.Now().UnixNano() - int64(binary.BigEndian.Uint64(buf[:nbyte])))
		fmt.Println(count, ": Latency : ", latency, "ns")
		f.WriteString(strconv.FormatInt(latency, 10) + "\n")
		count = count + 1
		time.Sleep(100 * time.Millisecond)
	}
}
