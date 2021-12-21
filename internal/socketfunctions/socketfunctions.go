/*
NOTICE

Notice: This computer software was prepared Alliance for Sustainable Energy,
LLC, hereinafter the Contractor, under Contract DE-AC36-08GO28308 with the
Department of Energy (DOE). All rights in the computer software are reserved by
DOE on behalf of the United States Government and the Contractor as provided in
the Contract. You are authorized to use this computer software for Governmental
purposes but it is not to be released or distributed to the public. NEITHER THE
GOVERNMENT NOR THE CONTRACTOR MAKES ANY WARRANTY, EXPRESS OR IMPLIED, OR
ASSUMES ANY LIABILITY FOR THE USE OF THIS SOFTWARE. This notice including this
sentence must appear on any copies of this computer software.

NOTICE: EXPORT OR DEEMED EXPORT OF THIS SOFTWARE MAY VIOLATE U.S. EXPORT
CONTROLS. DO NOT PROVIDE THIS SOFTWARE (OR ACCESS TO THIS SOFTWARE) TO ANY
NON-U.S. CITIZEN WITHOUT PROPER AUTHORIZATION. ALLIANCE WILL NOT BE RESPONSIBLE
FOR ANY VIOLATION OF EXPORT CONTROL BY ANY OTHER PARTY.
*/
package socketfunctions

import (
	"log"
	"net"
	"strconv"
	"time"

	"moduleot/internal/ifacefunctions"
	"moduleot/internal/securepacket"

	proto "github.com/golang/protobuf/proto"
	"github.com/spacemonkeygo/openssl"
)

type TLSPacket struct {
	ClientIP string
	Packet   securepacket.Packet
}

type OpenSSLClientData struct {
	Certificate string
	Key         string
	TLSRx       chan TLSPacket
	TLSTx       chan TLSPacket
	NetType     string
	IP          string
	PORT        string
	NetworkChan chan TLSPacket
	Parenterrc  chan OpenSSLClientData
	CloseChan   chan bool
}

type TCPClientData struct {
	TCPRx      chan securepacket.Packet
	TCPTx      chan securepacket.Packet
	CloseChan  chan bool
	NetType    string
	DestIP     string
	DestPort   string
	SrcIP      string
	SrcPort    string
	Parenterrc chan TCPClientData
}

type ServerInstance struct {
	IP                string
	PORT              string
	WHITELIST         []string
	ClientConnections map[string]net.Conn
	Listener          net.Listener
}

// OpenSSL Functions

func (serv *ServerInstance) SpawnOpenSSLServer(certificate string, key string, TLSRx chan<- TLSPacket, TLSTx <-chan TLSPacket, netType string, parenterrc chan<- error) {
	newConns := make(chan net.Conn, 128)
	deadConns := make(chan net.Conn, 128)
	warnCount := make(map[string]int)
	errc := make(chan error)
	version := openssl.TLS
	ctx, err := openssl.NewCtxFromFilesWithVersion(certificate, key, version)
	if err != nil {
		log.Println(err)
	}
	ctx.SetVerifyMode(openssl.VerifyPeer)
	err = ctx.SetCipherSuites("TLS_AES_128_CCM_8_SHA256")
	serv.Listener, err = openssl.Listen(netType, serv.IP+":"+serv.PORT, ctx)
	if err != nil {
		log.Println("TLS Server Closing...")
		parenterrc <- err
		return
	}
	defer serv.Listener.Close()
	go func() {
		for {
			whitelisted := false
			conn, _ := serv.Listener.Accept()

			remoteAddr, err := net.ResolveTCPAddr(netType, conn.RemoteAddr().String())
			if err != nil {
				continue
			}
			remoteIP := remoteAddr.IP.String()
			for _, whitelistedIP := range serv.WHITELIST {
				if remoteIP == whitelistedIP {
					whitelisted = true
				}
			}
			if whitelisted {
				serv.ClientConnections[remoteIP] = conn
				newConns <- conn
				log.Println("New ModuleOT client connected:", remoteIP+":"+serv.PORT)
			} else {
				log.Println("WARNING: Non-whitelisted connection attempted from ", remoteIP, "- Closing connection...")
				if val, ok := warnCount[remoteIP]; ok {
					warnCount[remoteIP] = val + 1
					if warnCount[remoteIP] > 10 {
						log.Println("ALERT: Too many Non-whitelisted connections attempted from ", remoteIP, "- blocking connection...")
						ifacefunctions.DenySrcIP(remoteIP)
					}
				} else {
					warnCount[remoteIP] = 0
				}
				conn.Close()
			}

		}
	}()
	for {
		select {
		case conn := <-newConns:
			var connIP string
			for connectedClient, connection := range serv.ClientConnections {
				if conn == connection {
					connIP = connectedClient
				}
			}
			go func(connIP string) {
				buf := make([]byte, 1024)
				for {
					nbyte, err := conn.Read(buf)
					if err != nil {
						deadConns <- conn
						break
					} else {
						tlsPacket := TLSPacket{}
						tlsPacket.ClientIP = connIP
						_ = proto.Unmarshal(buf[:nbyte], &tlsPacket.Packet)
						TLSRx <- tlsPacket
					}
				}
			}(connIP)
		case deadConn := <-deadConns:
			_ = deadConn.Close()
			for clientIP, connection := range serv.ClientConnections {
				if connection == deadConn {
					delete(serv.ClientConnections, clientIP)
				}
			}
		case packet := <-TLSTx:
			out, _ := proto.Marshal(&packet.Packet)
			_, err := serv.ClientConnections[packet.ClientIP].Write(out)
			if err != nil {
				deadConns <- serv.ClientConnections[packet.ClientIP]
			}
		case err := <-errc:
			log.Println("TLS Server Closing...")
			parenterrc <- err
			return
		}
	}
}

func ConnectOpenSSLClient(certificate string, key string, TLSRx chan TLSPacket, TLSTx chan TLSPacket, netType string, IP string, PORT string, networkChan chan TLSPacket, parenterrc chan OpenSSLClientData, closeChan chan bool) {
	errc := make(chan error)
	log.Println("TLS client dialing server at ", IP, ":", PORT)
	ctx, err := openssl.NewCtx()
	if err != nil {
		errc <- err
	}
	err = ctx.LoadVerifyLocations("/etc/ssl/certs/rootCA.pem", "")
	if err != nil {
		errc <- err
	}
	ctx.SetVerifyMode(openssl.VerifyPeer)
	err = ctx.SetCipherSuites("TLS_AES_128_CCM_8_SHA256")
	if err != nil {
		log.Println(err)
	}
	connection, err := openssl.Dial(netType, IP+":"+PORT, ctx, 1)
	for err != nil {
		log.Println("TLS client connection ERROR: dial:", err)
		time.Sleep(1 * time.Second)
		connection, err = openssl.Dial(netType, IP+":"+PORT, ctx, 1)
	}
	log.Println("TLS client connected to server at ", IP, ":", PORT)
	defer connection.Close()
	go func() {
		buf := make([]byte, 1024)
		for {
			nbyte, err := connection.Read(buf)
			if err != nil {
				log.Println("TLS read Error: ", err)
				errc <- err
				break
			} else {
				packet := securepacket.Packet{}
				_ = proto.Unmarshal(buf[:nbyte], &packet)
				tlsPacket := TLSPacket{}
				tlsPacket.ClientIP = IP
				tlsPacket.Packet = packet
				if packet.Packtype != "" {
					networkChan <- tlsPacket
				} else {
					TLSRx <- tlsPacket
				}
			}
		}
	}()
	for {
		select {
		case err = <-errc:
			log.Println("OpenSSL client closing. ERROR: ", err)
			clientData := OpenSSLClientData{}
			clientData.Certificate = certificate
			clientData.Key = key
			clientData.TLSRx = TLSRx
			clientData.TLSTx = TLSTx
			clientData.NetType = netType
			clientData.IP = IP
			clientData.PORT = PORT
			clientData.NetworkChan = networkChan
			clientData.Parenterrc = parenterrc
			clientData.CloseChan = closeChan
			parenterrc <- clientData
			return
		case secPacket := <-TLSTx:

			out, _ := proto.Marshal(&secPacket.Packet)
			_, err = connection.Write(out)
			if err != nil {
				log.Println("TLS Write Error: ", err)
				connection.Close()
				connection, err = openssl.Dial(netType, IP+":"+PORT, ctx, 1)
				for err != nil {
					log.Println("TLS client connection retry ERROR: dial:", err)
					time.Sleep(1 * time.Second)
					connection, err = openssl.Dial(netType, IP+":"+PORT, ctx, 1)
				}
				log.Println("TLS client connected:", IP+":"+PORT)
				defer connection.Close()
				_, err = connection.Write(out)
			}
		case signal := <-closeChan:
			if signal == true {
				log.Println("TLS Client closing connection to ", IP+":"+PORT)
				connection.Close()
				return
			}
		}
	}

}

// TCP Functions

func (serv *ServerInstance) SpawnTCPServer(TCPRx chan<- securepacket.Packet, TCPTx <-chan securepacket.Packet, discChannel chan<- securepacket.Packet, netType string, closeChan <-chan bool) {
	newConns := make(chan net.Conn, 128)
	deadConns := make(chan net.Conn, 128)
	warnCount := make(map[string]int)
	var conn net.Conn
	var err error
	serv.Listener, err = net.Listen(netType, serv.IP+":"+serv.PORT)
	if err != nil {
		panic(err)
	}
	defer serv.Listener.Close()
	log.Println("TCP Server Started at", serv.IP+":"+serv.PORT)
	whitelisted := false
	go func() {
		for {
			conn, err := serv.Listener.Accept()
			whitelisted = false
			if err != nil {
				log.Fatalln(err)
			}
			remoteAddr, _ := net.ResolveTCPAddr(netType, conn.RemoteAddr().String())
			localAddr, _ := net.ResolveTCPAddr(netType, conn.LocalAddr().String())
			localIP := localAddr.IP.String()
			localPort := strconv.Itoa(localAddr.Port)
			remoteIP := remoteAddr.IP.String()
			remotePort := strconv.Itoa(remoteAddr.Port)
			for _, whitelistedIP := range serv.WHITELIST {
				if remoteIP == whitelistedIP {
					whitelisted = true
				}
			}
			if whitelisted {
				warnCount[remoteIP] = 0
				serv.ClientConnections[remoteIP] = conn
				log.Println("New TCP client connected:", remoteIP+":"+remotePort)
				newConns <- conn
				netUpdate := securepacket.Packet{}
				netUpdate.SrcIP = remoteIP
				netUpdate.SrcPort = remotePort
				netUpdate.DestIP = localIP
				netUpdate.DestPort = localPort
				netUpdate.Packtype = "OPEN-TCP"
				discChannel <- netUpdate
			} else {
				log.Println("WARNING: Non-whitelisted connection attempted from ", remoteIP, "- Closing connection...")
				if val, ok := warnCount[remoteIP]; ok {
					warnCount[remoteIP] = val + 1
					if warnCount[remoteIP] > 10 {
						log.Println("ALERT: Too many Non-whitelisted connections attempted from ", remoteIP, "- blocking connection...")
						ifacefunctions.DenySrcIP(remoteIP)
					}
				} else {
					warnCount[remoteIP] = 0
				}
				conn.Close()
			}

		}
	}()
	for {
		select {
		case conn = <-newConns:
			go func() {
				buf := make([]byte, 1024)
				for {
					nbyte, err := conn.Read(buf)
					if err != nil {
						deadConns <- conn
						break
					} else {
						packet := securepacket.Packet{}
						remoteAddr, _ := net.ResolveTCPAddr(netType, conn.RemoteAddr().String())
						packet.SrcIP = remoteAddr.IP.String()
						packet.SrcPort = strconv.Itoa(remoteAddr.Port)
						localAddr, _ := net.ResolveTCPAddr(netType, conn.LocalAddr().String())
						packet.DestIP = localAddr.IP.String()
						packet.DestPort = strconv.Itoa(localAddr.Port)
						packet.Payload = buf[:nbyte]
						TCPRx <- packet

					}
				}
			}()
		case deadConn := <-deadConns:
			_ = deadConn.Close()
			remoteAddr, _ := net.ResolveTCPAddr(netType, deadConn.RemoteAddr().String())
			localAddr, _ := net.ResolveTCPAddr(netType, deadConn.LocalAddr().String())
			localIP := localAddr.IP.String()
			localPort := strconv.Itoa(localAddr.Port)
			remoteIP := remoteAddr.IP.String()
			remotePort := strconv.Itoa(remoteAddr.Port)
			netUpdate := securepacket.Packet{}
			netUpdate.SrcIP = remoteIP
			netUpdate.SrcPort = remotePort
			netUpdate.DestIP = localIP
			netUpdate.DestPort = localPort
			netUpdate.Packtype = "CLOSE-TCP"
			for clientIP, connection := range serv.ClientConnections {
				if connection == deadConn {
					delete(serv.ClientConnections, clientIP)
				}
			}
		case OutMsg := <-TCPTx:
			_, err := serv.ClientConnections[OutMsg.DestIP].Write(OutMsg.Payload)
			if err != nil {
				deadConns <- serv.ClientConnections[OutMsg.DestIP]
			}
		case signal := <-closeChan:
			if signal == true {
				log.Println("TLS Server ", serv.IP+":"+serv.PORT, " Closing")
				serv.Listener.Close()
				return
			}
		}
	}
}

func ConnectTCPClient(TCPRx chan securepacket.Packet, TCPTx chan securepacket.Packet, closeChan chan bool, netType string, IP string, PORT string, SRCIP string, SRCPORT string, parenterrc chan TCPClientData) {

	log.Println("TCP client (Remote Src: ", SRCIP, ":", SRCPORT, ") connecting to server at ", IP, ":", PORT)
	errc := make(chan error)
	connection, err := net.Dial(netType, IP+":"+PORT)
	for err != nil {
		errc <- err
	}
	log.Println("TCP client (Remote Src: ", SRCIP, ":", SRCPORT, ") connected: ", IP+":"+PORT)
	defer connection.Close()
	go func() {
		buf := make([]byte, 1024)
		for {
			nbyte, err := connection.Read(buf)
			if err != nil {
				errc <- err
				closeChan <- true
				break
			} else {
				//remoteAddr, _ := net.ResolveTCPAddr(netType, connection.RemoteAddr().String())
				//localAddr, _ := net.ResolveTCPAddr(netType, connection.LocalAddr().String())
				packet := securepacket.Packet{}
				packet.Payload = buf[:nbyte]
				packet.SrcIP = IP
				packet.SrcPort = PORT
				packet.DestIP = SRCIP
				packet.DestPort = SRCPORT
				TCPRx <- packet
			}
		}
	}()
	for {
		select {
		case err = <-errc:
			log.Println("TCP client closing. ERROR: ", err)
			clientData := TCPClientData{}
			clientData.TCPRx = TCPRx
			clientData.TCPTx = TCPTx
			clientData.CloseChan = closeChan
			clientData.NetType = netType
			clientData.DestIP = IP
			clientData.DestPort = PORT
			clientData.SrcIP = SRCIP
			clientData.SrcPort = SRCPORT
			clientData.Parenterrc = parenterrc
			parenterrc <- clientData
		case packet := <-TCPTx:
			_, err = connection.Write(packet.Payload)
			if err != nil {
				log.Println("TCP Write Error: ", err)
				connection.Close()
				connection, err = net.Dial(netType, IP+":"+PORT)
				for err != nil {
					log.Println("TCP client connection retry ERROR: dial:", err)
					time.Sleep(1 * time.Second)
					connection, err = net.Dial(netType, IP+":"+PORT)
				}
				log.Println("TCP client (Remote Src: ", SRCIP, ":", SRCPORT, ") connected:", IP+":"+PORT)
				defer connection.Close()
				_, err = connection.Write(packet.Payload)
			}
		case closeSignal := <-closeChan:
			if closeSignal {
				log.Println("Closing TCP Connection to: ", IP+":"+PORT)
				connection.Close()
				return
			}
		}
	}
}

func ConnectSendTCP(payload []byte, netType string, IP string, PORT string) {
	log.Println("TCP client connecting to server at ", IP, ":", PORT)
	connection, err := net.Dial(netType, IP+":"+PORT)
	count := 0
	for err != nil {
		if count > 2 {
			break
		} else {
			log.Println("TCP client connection ERROR: dial:", err)
			time.Sleep(200 * time.Millisecond)
			connection, err = net.Dial(netType, IP+":"+PORT)
		}
	}
	_, err = connection.Write(payload)
	if err != nil {
		log.Println("TCP Write Error: ", err)
	}
	connection.Close()
}
