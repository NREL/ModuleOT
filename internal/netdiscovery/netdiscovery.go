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
package netdiscovery

import (
	"fmt"
	"log"
	"os"
	"time"

	"moduleot/internal/securepacket"

	"github.com/Ullaakut/nmap"
)

type DiscoveryInstance struct {
	Ports        []string
	Whitelist    []string
	Ignorelist   []string
	HostStateMap map[string]string
	IpLAN        []string
	LANMask      string
	LANIface     string
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func (discInst *DiscoveryInstance) DiscoverHost(discoveryChannel chan<- securepacket.Packet, interruptchan <-chan os.Signal) {

	var ports string
	for i := 0; i < (len(discInst.Ports) - 1); i++ {
		ports = ports + discInst.Ports[i] + ","
	}
	ports = ports + discInst.Ports[len(discInst.Ports)-1]

	var oldslice []string
	prevHostNo := 0
	var LAN []string
	var slice []string
	if discInst.LANMask != "" {
		LAN = discInst.IpLAN
		LAN[0] = discInst.IpLAN[0] + "/" + discInst.LANMask
		log.Println("NETWORK DISCOVERY Started On ", discInst.IpLAN[0]+"/"+discInst.LANMask)
	} else {
		LAN = discInst.IpLAN
		log.Println("NETWORK DISCOVERY Started On ", discInst.IpLAN)
	}
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(LAN...),
		nmap.WithPorts(ports),
		//nmap.WithInterface(discInst.LANIface),
		nmap.WithSkipHostDiscovery(),
		nmap.WithDisabledDNSResolution(),
	)
	if err != nil {
		log.Fatalln("unable to create nmap scanner: ", err)
	}
	netDiscoveryTicker := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-netDiscoveryTicker.C:
			result, _, err := scanner.Run()
			if err != nil {
				log.Fatalln("nmap scan failed: ", err)
			}
			//log.Println("HostStateMap: ", discInst.HostStateMap)
			for _, host := range result.Hosts {
				newHost := host.Addresses[0].Addr
				if stringInSlice(newHost, discInst.Whitelist) == true && stringInSlice(newHost, discInst.Ignorelist) != true {
					slice = append(slice, newHost)
					for _, port := range host.Ports {
						portid := fmt.Sprintf("%d", port.ID)
						if port.State.State == "open" {
							var netinfopack securepacket.Packet
							netinfopack.DestIP = newHost
							netinfopack.DestPort = portid
							netinfopack.Packtype = "OPEN"
							if discInst.HostStateMap[newHost+":"+portid] != "OPEN" {
								discInst.HostStateMap[newHost+":"+portid] = "OPEN"
								discoveryChannel <- netinfopack
							}
						} else {
							if discInst.HostStateMap[newHost+":"+portid] == "OPEN" && port.State.State == "closed" {
								var netinfopack securepacket.Packet
								netinfopack.DestIP = newHost
								netinfopack.DestPort = portid
								netinfopack.Packtype = "CLOSED"
								if discInst.HostStateMap[newHost+":"+portid] != "CLOSED" {
									discInst.HostStateMap[newHost+":"+portid] = "CLOSED"
									discoveryChannel <- netinfopack
								}
							}
						}
					}
				}
			}
			if len(result.Hosts) != prevHostNo {
				log.Printf("Nmap done: %d hosts up scanned in %3f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
				for _, hostIP := range oldslice {
					// Check if an interface has closed
					if stringInSlice(hostIP, slice) != true {
						var netinfopack securepacket.Packet
						netinfopack.DestIP = hostIP
						netinfopack.Packtype = "CLOSEINTERFACE"
						discoveryChannel <- netinfopack
					}
				}
				oldslice = slice
				prevHostNo = len(result.Hosts)
			}
		case <-interruptchan:
			return
		}
	}
}
