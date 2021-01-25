/*
NOTICE
Notice: This computer software was prepared Alliance for Sustainable Energy, LLC, hereinafter the Contractor,
under Contract DE-AC36-08GO28308 with the Department of Energy (DOE). All rights in the computer software are
reserved by DOE on behalf of the United States Government and the Contractor as provided in the Contract. You
are authorized to use this computer software for Governmental purposes but it is not to be released or distributed
to the public. NEITHER THE GOVERNMENT NOR THE CONTRACTOR MAKES ANY WARRANTY, EXPRESS OR IMPLIED, OR ASSUMES ANY
LIABILITY FOR THE USE OF THIS SOFTWARE. This notice including this sentence must appear on any copies of this
computer software.
NOTICE: EXPORT OR DEEMED EXPORT OF THIS SOFTWARE MAY VIOLATE U.S. EXPORT CONTROLS. DO NOT PROVIDE THIS SOFTWARE
(OR ACCESS TO THIS SOFTWARE) TO ANY NON-U.S. CITIZEN WITHOUT PROPER AUTHORIZATION. ALLIANCE WILL NOT BE RESPONSIBLE
FOR ANY VIOLATION OF EXPORT CONTROL BY ANY OTHER PARTY.
*/

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"ifacefunctions"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"netdiscovery"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"securepacket"
	"socketfunctions"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/sha3"
)

const (
	CONFIGFILE = "/etc/moduleot/config.json"
	CERTFILE   = "/etc/ssl/certs/mot_servcert.pem"
	KEYFILE    = "/etc/ssl/certs/mot_servkey.key"
	//CERTFILE   = "/etc/ssl/certs/mot_clicert.pem"
	//KEYFILE    = "/etc/ssl/certs/mot_clikey.key"
	MAXTLS     = 1024
	MAXTCP     = 10
)

type Configuration struct {
	WANINTERFACE   string
	WANIP          string
	WANMASK        string
	GATEWAYIP      string
	LANINTERFACE   string
	LANIP          string
	MANINTERFACE   string
	MANIP          string
	LANMASK        string
	TLSPORT        string
	TCPPORT        string
	WHITELIST      []string
	NETWHITELIST   []string
	MODBUSIP       string
	PASSTHRUIP     []string
	PROTECTEDPORTS []string
	PASSTHRUPORTS  []string
}

type MOTApp struct {
	TLSTxChanMap map[string]chan socketfunctions.TLSPacket
	TLSRxChanMap map[string]chan socketfunctions.TLSPacket
	TCPTxChanMap map[string]chan securepacket.Packet
	TCPRxChanMap map[string]chan securepacket.Packet
	ClientIPMap  map[string]string
	CloseChanMap map[string]chan bool
	Config       Configuration
	IntMap       map[string]int
}

func checkFileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}

	return true
}

func (app *MOTApp) TCPpacketRouter(rx <-chan securepacket.Packet) {
	for {
		packet := <-rx
		//log.Println("Routing TCP Packet: ", packet, "TO: ", app.ClientIPMap[packet.DestIP+":"+packet.DestPort])
		tlsPacket := socketfunctions.TLSPacket{}
		tlsPacket.Packet = packet
		tlsPacket.ClientIP = app.ClientIPMap[packet.DestIP+":"+packet.DestPort]
		app.TLSTxChanMap[app.Config.WANIP+":"+app.Config.TLSPORT] <- tlsPacket
	}
}

func (app *MOTApp) TLSpacketRouter(rx <-chan socketfunctions.TLSPacket) {
	for {
		packet := <-rx
		//log.Println("Routing TLS Packet: ", packet, "TO: ", packet.Packet.DestIP+":"+packet.Packet.DestPort, "FROM: ", packet.Packet.SrcIP+":"+packet.Packet.SrcPort)
		_, ok := app.TCPTxChanMap[packet.Packet.SrcIP+":"+packet.Packet.SrcPort]
		if ok {
			app.TCPTxChanMap[packet.Packet.SrcIP+":"+packet.Packet.SrcPort] <- packet.Packet
		} else {
			log.Println("Unable to route TLS Packet: ", packet, "TO: ", packet.Packet.DestIP+":"+packet.Packet.DestPort, "FROM: ", packet.Packet.SrcIP+":"+packet.Packet.SrcPort, " Dropping...")
			//go socketfunctions.ConnectSendTCP(packet.Packet.Payload, "tcp", packet.Packet.DestIP, packet.Packet.DestPort)
		}
	}
}

func removeFromSlice(slice []string, index int) []string {
	slice[index] = slice[len(slice)-1]
	return slice[:len(slice)-1]
}

func main() {

	// Check for command-line flags
	logfileFlag := flag.Bool("logfile", true, "if true, logs out to file at /var/log/moduleot")
	flag.Parse()

	// Configure Logging
	if *logfileFlag {
		logfile, err := os.OpenFile("/var/log/moduleot/"+time.Now().String()[:28]+".log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			log.Fatal(err)
		}
		defer logfile.Close()
		log.SetOutput(logfile)
	}

	//Verify hash of executable
	file, _ := ioutil.ReadFile("/etc/moduleot/Hashfile")
	correctHashString := string(file)
	correctHashString = strings.TrimSpace(correctHashString)
	file, _ = ioutil.ReadFile("/usr/bin/motApp")
	hash := sha3.Sum256(file)
	hashString := fmt.Sprintf("%x", hash)
	if hashString != correctHashString {
		log.Println("Incorrect firmware Hash: ", hashString)
		log.Println("***DEV MESSAGE. will be deleted before release***")
		runtime.Goexit()
		os.Exit(0)
	}
	// Initialize Application Instance
	application := MOTApp{}

	// Make Channel and IP Maps for packet routing
	application.TLSTxChanMap = make(map[string]chan socketfunctions.TLSPacket)
	application.TLSRxChanMap = make(map[string]chan socketfunctions.TLSPacket)
	application.TCPTxChanMap = make(map[string]chan securepacket.Packet)
	application.TCPRxChanMap = make(map[string]chan securepacket.Packet)
	application.ClientIPMap = make(map[string]string)
	application.CloseChanMap = make(map[string]chan bool)
	application.IntMap = make(map[string]int)

	if checkFileExists(CONFIGFILE) {
		file, _ := os.Open(CONFIGFILE)
		decoder := json.NewDecoder(file)
		err := decoder.Decode(&application.Config)
		if err != nil {
			log.Println("Config parsing ERROR:", err)
			runtime.Goexit()
			os.Exit(0)
		}
		file.Close()
	} else {
		log.Println("ERROR: Config File Missing. ModuleOT Application Closing...")
		runtime.Goexit()
		os.Exit(0)
	}

	// Create Interrupt channel to handle termination
	interruptchan := make(chan os.Signal, 5)
	signal.Notify(interruptchan, os.Interrupt, syscall.SIGTERM)

	// Enable and configure firewall to allow ssh
	ifacefunctions.ResetFirewall()
	ifacefunctions.EnableFirewall()
	defer ifacefunctions.ResetFirewall()
	for _, ip := range application.Config.WHITELIST {
		if ip != application.Config.WANIP {
			ifacefunctions.AllowSrcIPPort(ip, application.Config.WANIP, application.Config.TLSPORT)
			ifacefunctions.AllowSrcIPProtocol(ip, "22")
		}
	}
	ifacefunctions.AllowSrcIPProtocol(application.Config.LANIP+"/"+application.Config.LANMASK, "22")
	ifacefunctions.AllowSrcIPProtocol(application.Config.MANIP+"/30", "22")
	ifacefunctions.ProtocolRateLimit("ssh")

	// Configure firewall to allow Passthru ports

	// Configure the MAN Interface
	if application.Config.MANIP != "" {
		ifacefunctions.SetInterfaceIP(application.Config.MANINTERFACE, application.Config.MANIP, "30")
	}

	// Configure the WAN Interface
	if application.Config.WANIP != "" {
		ifacefunctions.SetInterfaceIP(application.Config.WANINTERFACE, application.Config.WANIP, application.Config.WANMASK)
		for _, ip := range application.Config.WHITELIST {
			if ip != application.Config.WANIP {
				for _, port := range application.Config.PASSTHRUPORTS {
					ifacefunctions.AllowSrcIPProtocol(ip, port)
				}
			}
		}
		//ifacefunctions.AllowSrcIPInterface(application.Config.WANIP, "out", application.Config.WANINTERFACE)
	}

	// Configure default gateway
	if application.Config.GATEWAYIP != "" {
		ifacefunctions.AddDefaultGateway(application.Config.GATEWAYIP)
	}

	// Allow forwarding from LAN to WAN
	ifacefunctions.AllowForwardInterface(application.Config.LANINTERFACE, application.Config.WANINTERFACE)

	// Allow forwarding for Passthru
	for _, port := range application.Config.PASSTHRUPORTS {
		ifacefunctions.AllowForwardInterfacePort(application.Config.WANINTERFACE, port)
	}

	// Configure the LAN Interface
	if application.Config.LANIP != "" {
		ifacefunctions.SetInterfaceIP(application.Config.LANINTERFACE, application.Config.LANIP, application.Config.LANMASK)
		ifacefunctions.AllowSrcIP(application.Config.LANIP + "/" + application.Config.LANMASK)
	}

	// Setup Channels
	networkChan := make(chan socketfunctions.TLSPacket, 5)
	servererrc := make(chan error)
	clienterrc := make(chan socketfunctions.OpenSSLClientData)
	tcpclienterrc := make(chan socketfunctions.TCPClientData)

	// Start OpenSSL Server
	ServerInst := socketfunctions.ServerInstance{}
	ServerInst.IP = application.Config.WANIP
	ServerInst.PORT = application.Config.TLSPORT
	ServerInst.WHITELIST = application.Config.WHITELIST
	ServerInst.ClientConnections = make(map[string]net.Conn)
	ServerTLSRx := make(chan socketfunctions.TLSPacket, MAXTLS)
	ServerTLSTx := make(chan socketfunctions.TLSPacket, MAXTLS)
	application.TLSTxChanMap[application.Config.WANIP+":"+application.Config.TLSPORT] = ServerTLSTx
	application.TLSRxChanMap[application.Config.WANIP+":"+application.Config.TLSPORT] = ServerTLSRx
	application.IntMap[application.Config.LANIP] = 0
	go ServerInst.SpawnOpenSSLServer(CERTFILE, KEYFILE, ServerTLSRx, ServerTLSTx, "tcp", servererrc)

	// Create virtual interface and start MODBUS Relay with configured IP
	if application.Config.MODBUSIP != "" {
		// Get a unique interface number
		index := rand.Intn(999)
		ifacefunctions.MakeVirtualInterface(application.Config.LANINTERFACE, index, application.Config.MODBUSIP)
		defer ifacefunctions.CloseVirtualInterface(application.Config.LANINTERFACE, index)
		application.IntMap[application.Config.MODBUSIP] = index
		cmd := exec.Command("python", "/usr/share/moduleot/serialForwarder.py", "--ip", application.Config.MODBUSIP)
		err := cmd.Run()
		if err != nil {
			log.Println("Modbus Forwarder Error: ", err)
		}
	}

	//Start network discovery instances
	scanIPs := []string{}
	for _, IP := range application.Config.WHITELIST {
		if IP != application.Config.WANIP {
			scanIPs = append(scanIPs, IP)
		}
	}
	tlsDiscInst := netdiscovery.DiscoveryInstance{}
	tlsdiscoveryChannel := make(chan securepacket.Packet, 5)
	tlsDiscInst.Ports = []string{application.Config.TLSPORT}
	tlsDiscInst.Whitelist = application.Config.WHITELIST
	tlsDiscInst.Ignorelist = append(tlsDiscInst.Ignorelist, application.Config.WANIP)
	tlsDiscInst.HostStateMap = make(map[string]string)
	tlsDiscInst.IpLAN = scanIPs
	tlsDiscInst.LANMask = ""
	tlsDiscInst.LANIface = application.Config.LANINTERFACE
	go tlsDiscInst.DiscoverHost(tlsdiscoveryChannel, interruptchan)

	scanIPs = []string{}
	for _, IP := range application.Config.NETWHITELIST {
		if IP != application.Config.LANIP {
			scanIPs = append(scanIPs, IP)
		}
	}
	tcpDiscInst := netdiscovery.DiscoveryInstance{}
	tcpdiscoveryChannel := make(chan securepacket.Packet, 5)
	tcpDiscInst.Ports = application.Config.PROTECTEDPORTS
	tcpDiscInst.Whitelist = application.Config.NETWHITELIST
	tcpDiscInst.Ignorelist = append(tcpDiscInst.Ignorelist, application.Config.LANIP)
	tcpDiscInst.HostStateMap = make(map[string]string)
	tcpDiscInst.IpLAN = scanIPs
	tcpDiscInst.LANMask = ""
	tcpDiscInst.LANIface = application.Config.WANINTERFACE
	go tcpDiscInst.DiscoverHost(tcpdiscoveryChannel, interruptchan)

	netUpdateMap := make(map[string]securepacket.Packet)
	netUpdateTicker := time.NewTicker(1 * time.Second)
	// Main loop
	for {
		select {
		case netUpdate := <-networkChan:
			//log.Println("Got Net Discover update: ", netUpdate)
			switch netUpdate.Packet.Packtype {
			case "OPEN":
				// Check if server instance already exists
				if _, ok := application.CloseChanMap[netUpdate.Packet.DestIP+":"+netUpdate.Packet.DestPort]; !ok {
					// Check if a new Virtual interface needs to be made
					if _, ok = application.IntMap[netUpdate.Packet.DestIP]; !ok {
						// Get a unique interface number
						var index int
						existsFlag := true
						for existsFlag {
							existsFlag = false
							index = rand.Intn(999)
							for _, intNo := range application.IntMap {
								if index == intNo {
									existsFlag = true
								}
							}
						}
						ifacefunctions.MakeVirtualInterface(application.Config.LANINTERFACE, index, netUpdate.Packet.DestIP+"/32")
						defer ifacefunctions.CloseVirtualInterface(application.Config.LANINTERFACE, index)
						application.IntMap[netUpdate.Packet.DestIP] = index
						tcpDiscInst.Ignorelist = append(tcpDiscInst.Ignorelist, netUpdate.Packet.DestIP)
					}

					TCPServerInst := socketfunctions.ServerInstance{}
					TCPServerInst.IP = netUpdate.Packet.DestIP
					TCPServerInst.PORT = netUpdate.Packet.DestPort
					TCPServerInst.WHITELIST = application.Config.NETWHITELIST
					TCPServerInst.ClientConnections = make(map[string]net.Conn)

					TCPRx := make(chan securepacket.Packet, MAXTCP)
					TCPTx := make(chan securepacket.Packet, MAXTCP)
					closeChan := make(chan bool)

					go TCPServerInst.SpawnTCPServer(TCPRx, TCPTx, tcpdiscoveryChannel, "tcp", closeChan)
					application.TCPTxChanMap[netUpdate.Packet.DestIP+":"+netUpdate.Packet.DestPort] = TCPTx
					application.TCPRxChanMap[netUpdate.Packet.DestIP+":"+netUpdate.Packet.DestPort] = TCPRx
					application.CloseChanMap[netUpdate.Packet.DestIP+":"+netUpdate.Packet.DestPort] = closeChan
					go application.TCPpacketRouter(TCPRx)
					application.ClientIPMap[netUpdate.Packet.DestIP+":"+netUpdate.Packet.DestPort] = netUpdate.ClientIP
				}
			case "OPEN-TCP":
				if _, ok := application.ClientIPMap[netUpdate.Packet.SrcIP+":"+netUpdate.Packet.SrcPort]; !ok {
					// Check if a new Virtual interface needs to be made
					if _, ok := application.IntMap[netUpdate.Packet.SrcIP]; !ok {
						// Get a unique interface number
						var index int
						existsFlag := true
						for existsFlag {
							existsFlag = false
							index = rand.Intn(999)
							for _, intNo := range application.IntMap {
								if index == intNo {
									existsFlag = true
								}
							}
						}
						ifacefunctions.MakeVirtualInterface(application.Config.LANINTERFACE, index, netUpdate.Packet.SrcIP+"/32")
						defer ifacefunctions.CloseVirtualInterface(application.Config.LANINTERFACE, index)
						application.IntMap[netUpdate.Packet.SrcIP] = index
						tcpDiscInst.Ignorelist = append(tcpDiscInst.Ignorelist, netUpdate.Packet.SrcIP)
					}

					TCPRx := make(chan securepacket.Packet, MAXTCP)
					TCPTx := make(chan securepacket.Packet, MAXTCP)
					closeChan := make(chan bool)

					go socketfunctions.ConnectTCPClient(TCPRx, TCPTx, closeChan, "tcp", netUpdate.Packet.DestIP, netUpdate.Packet.DestPort, netUpdate.Packet.SrcIP, netUpdate.Packet.SrcPort, tcpclienterrc)
					application.TCPTxChanMap[netUpdate.Packet.SrcIP+":"+netUpdate.Packet.SrcPort] = TCPTx
					application.TCPRxChanMap[netUpdate.Packet.SrcIP+":"+netUpdate.Packet.SrcPort] = TCPRx
					application.CloseChanMap[netUpdate.Packet.SrcIP+":"+netUpdate.Packet.SrcPort] = closeChan
					go application.TCPpacketRouter(TCPRx)
					application.ClientIPMap[netUpdate.Packet.SrcIP+":"+netUpdate.Packet.SrcPort] = netUpdate.ClientIP
				}
			case "CLOSE-TCP":
				if _, ok := application.ClientIPMap[netUpdate.Packet.SrcIP+":"+netUpdate.Packet.SrcPort]; ok {
					application.CloseChanMap[netUpdate.Packet.SrcIP+":"+netUpdate.Packet.SrcPort] <- true
					delete(application.TCPTxChanMap, netUpdate.Packet.SrcIP+":"+netUpdate.Packet.SrcPort)
					delete(application.TCPRxChanMap, netUpdate.Packet.SrcIP+":"+netUpdate.Packet.SrcPort)
					delete(application.ClientIPMap, netUpdate.Packet.SrcIP+":"+netUpdate.Packet.SrcPort)
				}
			case "CLOSED":
				if _, ok := application.CloseChanMap[netUpdate.Packet.DestIP+":"+netUpdate.Packet.DestPort]; ok {
					application.CloseChanMap[netUpdate.Packet.DestIP+":"+netUpdate.Packet.DestPort] <- true
					delete(application.TCPTxChanMap, netUpdate.Packet.DestIP+":"+netUpdate.Packet.DestPort)
					delete(application.TCPRxChanMap, netUpdate.Packet.DestIP+":"+netUpdate.Packet.DestPort)
					delete(application.CloseChanMap, netUpdate.Packet.DestIP+":"+netUpdate.Packet.DestPort)
				}
			case "CLOSEINTERFACE":
				log.Println("closing virtual interface:", netUpdate.Packet.DestIP)
				ifacefunctions.CloseVirtualInterface(application.Config.LANINTERFACE, application.IntMap[netUpdate.Packet.DestIP])
				tcpDiscInst.Ignorelist = removeFromSlice(tcpDiscInst.Ignorelist, application.IntMap[netUpdate.Packet.DestIP])
				delete(application.IntMap, netUpdate.Packet.DestIP)
			default:
				log.Println("Got NetUpdate of Unknown type: ", netUpdate.Packet.Packtype)
			}
		case tlsUpdate := <-tlsdiscoveryChannel:
			log.Println("Got TLS Discover update: ", tlsUpdate)
			switch tlsUpdate.Packtype {
			case "OPEN":
				TLSRx := make(chan socketfunctions.TLSPacket, MAXTLS)
				TLSTx := make(chan socketfunctions.TLSPacket, MAXTLS)
				closeChan := make(chan bool)
				go socketfunctions.ConnectOpenSSLClient(CERTFILE, KEYFILE, TLSRx, TLSTx, "tcp", tlsUpdate.DestIP, application.Config.TLSPORT, networkChan, clienterrc, closeChan)
				application.TLSTxChanMap[tlsUpdate.DestIP+":"+application.Config.TLSPORT] = TLSTx
				application.TLSRxChanMap[tlsUpdate.DestIP+":"+application.Config.TLSPORT] = TLSRx
				application.CloseChanMap[tlsUpdate.DestIP+":"+application.Config.TLSPORT] = closeChan
				go application.TLSpacketRouter(TLSRx)
			case "CLOSED":
				if _, ok := application.CloseChanMap[tlsUpdate.DestIP+":"+application.Config.TLSPORT]; ok {
					application.CloseChanMap[tlsUpdate.DestIP+":"+application.Config.TLSPORT] <- true
					delete(application.TLSTxChanMap, tlsUpdate.DestIP+":"+application.Config.TLSPORT)
					delete(application.TLSRxChanMap, tlsUpdate.DestIP+":"+application.Config.TLSPORT)
					delete(application.CloseChanMap, tlsUpdate.DestIP+":"+application.Config.TLSPORT)
				}
			case "CLOSEINTERFACE":
			default:
				log.Println("Got TLS NetUpdate of Unknown type: ", tlsUpdate.Packtype)
			}
		case tcpUpdate := <-tcpdiscoveryChannel:
			log.Println("Got TCP Discover update: ", tcpUpdate)
			netUpdateMap[tcpUpdate.DestIP+":"+tcpUpdate.DestPort] = tcpUpdate
			if tcpUpdate.Packtype == "OPEN-TCP" {
				application.TCPTxChanMap[tcpUpdate.SrcIP+":"+tcpUpdate.SrcPort] = application.TCPTxChanMap[tcpUpdate.DestIP+":"+tcpUpdate.DestPort]
				application.TCPRxChanMap[tcpUpdate.SrcIP+":"+tcpUpdate.SrcPort] = application.TCPRxChanMap[tcpUpdate.DestIP+":"+tcpUpdate.DestPort]
				for connectedClient := range ServerInst.ClientConnections {
					newPacket := socketfunctions.TLSPacket{}
					newPacket.ClientIP = connectedClient
					newPacket.Packet = tcpUpdate
					ServerTLSTx <- newPacket
				}
			}
			netUpdateMap[tcpUpdate.DestIP+":"+tcpUpdate.DestPort] = tcpUpdate
			if tcpUpdate.Packtype == "CLOSE-TCP" {
				delete(application.TCPTxChanMap, tcpUpdate.SrcIP+":"+tcpUpdate.SrcPort)
				delete(application.TCPRxChanMap, tcpUpdate.SrcIP+":"+tcpUpdate.SrcPort)
				for connectedClient := range ServerInst.ClientConnections {
					newPacket := socketfunctions.TLSPacket{}
					newPacket.ClientIP = connectedClient
					newPacket.Packet = tcpUpdate
					ServerTLSTx <- newPacket
				}
			}
		case <-netUpdateTicker.C:
			//log.Println("Sending NetUpdates")
			for _, val := range netUpdateMap {
				for connectedClient := range ServerInst.ClientConnections {
					//log.Println("Sending ", val, "::TO -> ", connectedClient)
					newPacket := socketfunctions.TLSPacket{}
					newPacket.ClientIP = connectedClient
					newPacket.Packet = val
					ServerTLSTx <- newPacket
				}
			}
		case err := <-servererrc:
			log.Println("ERROR: OpenSSL Server Failed - ", err)
			time.Sleep(1 * time.Second)
			log.Println("Attempting to restart Server")
			go ServerInst.SpawnOpenSSLServer(CERTFILE, KEYFILE, ServerTLSRx, ServerTLSTx, "tcp", servererrc)
		case clientInfo := <-clienterrc:
			log.Println("ERROR: OpenSSL Client Failed to ", clientInfo.IP, clientInfo.PORT)
			time.Sleep(500 * time.Millisecond)
			log.Println("Attempting to reconnect Client")
			go socketfunctions.ConnectOpenSSLClient(clientInfo.Certificate, clientInfo.Key, clientInfo.TLSRx, clientInfo.TLSTx, clientInfo.NetType, clientInfo.IP, clientInfo.PORT, clientInfo.NetworkChan, clientInfo.Parenterrc, clientInfo.CloseChan)
		case tcpClientInfo := <-tcpclienterrc:
			log.Println("ERROR: TCP Client Failed to ", tcpClientInfo.DestIP, tcpClientInfo.DestPort)
			time.Sleep(500 * time.Millisecond)
			log.Println("Attempting to reconnect Client")
			go socketfunctions.ConnectTCPClient(tcpClientInfo.TCPRx, tcpClientInfo.TCPTx, tcpClientInfo.CloseChan, tcpClientInfo.NetType, tcpClientInfo.DestIP, tcpClientInfo.DestPort, tcpClientInfo.SrcIP, tcpClientInfo.SrcPort, tcpClientInfo.Parenterrc)
			application.TCPTxChanMap[tcpClientInfo.SrcIP+":"+tcpClientInfo.SrcPort] = tcpClientInfo.TCPTx
			application.TCPRxChanMap[tcpClientInfo.SrcIP+":"+tcpClientInfo.SrcPort] = tcpClientInfo.TCPRx
			application.CloseChanMap[tcpClientInfo.SrcIP+":"+tcpClientInfo.SrcPort] = tcpClientInfo.CloseChan
		case <-interruptchan:
			log.Println("CTRLC")
			runtime.Goexit()
			os.Exit(0)
		}
	}

}
