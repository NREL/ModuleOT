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
package ifacefunctions

import (
	"log"
	"os/exec"
	"strconv"
)

func MakeVirtualInterface(device string, ifNum int, IP string) {
	cmd := exec.Command("ifconfig", device+":"+strconv.Itoa(ifNum), IP)
	err := cmd.Run()
	if err != nil {
		log.Fatalln("Virtual Interface creation Error: ", err)
	}
}

func CloseVirtualInterface(device string, ifNum int) {
	cmd := exec.Command("ifconfig", device+":"+strconv.Itoa(ifNum), "down")
	err := cmd.Run()
	if err != nil {
		log.Fatalln("Virtual Interface removal Error: ", err)
	}
}

func SetInterfaceIP(interfaceName, ipAddress, ipMask string) {
	cmd := exec.Command("ifconfig", interfaceName, ipAddress+"/"+ipMask)
	err := cmd.Run()
	if err != nil {
		log.Println("Interface IP configuration: ", err)
	}
}

// Firewall Functions

func EnableFirewall() {
	cmd := exec.Command("ufw", "--force", "enable")
	err := cmd.Run()
	if err != nil {
		log.Println("Firewall Enable Error: ", err)
	}
}

func DisableFirewall() {
	cmd := exec.Command("ufw", "disable")
	err := cmd.Run()
	if err != nil {
		log.Println("Firewall Disable Error: ", err)
	}
}

func ProtocolRateLimit(protocol string) {
	cmd := exec.Command("ufw", "limit", protocol)
	err := cmd.Run()
	if err != nil {
		log.Println("Firewall Protocol Rate Limit Error: ", err)
	}
}

func ResetFirewall() {
	cmd := exec.Command("ufw", "reset")
	err := cmd.Run()
	if err != nil {
		log.Println("Firewall Reset Error: ", err)
	}
}

func AllowProtocol(protocol string) {
	cmd := exec.Command("ufw", "allow", protocol)
	err := cmd.Run()
	if err != nil {
		log.Println("Firewall Allow Protocol Error: ", err)
	}
}

func AllowSrcIPProtocol(srcip, port string) {
	cmd := exec.Command("ufw", "allow", "from", srcip, "to", "any", "port", port)
	err := cmd.Run()
	if err != nil {
		log.Println("Firewall Allow SrcIP Protocol Error: ", err)
	}
}

func DenySrcIP(targetIP string) {
	cmd := exec.Command("ufw", "deny", "from", targetIP)
	err := cmd.Run()
	if err != nil {
		log.Println("Firewall Configuration Error: ", err)
	}
}

func AllowSrcIPInterface(targetIP, direction, vulInterface string) {
	cmd := exec.Command("ufw", "allow", direction, "on", vulInterface, "from", targetIP)
	err := cmd.Run()
	if err != nil {
		log.Println("Firewall Allow SrcIP Interface Error: ", err)
	}
}

func AllowSrcIP(targetIP string) {
	cmd := exec.Command("ufw", "allow", "in", "from", targetIP)
	err := cmd.Run()
	if err != nil {
		log.Println("Firewall Allow SrcIP Error: ", err)
	}
}

func AllowInterface(direction, secureInterface string) {
	cmd := exec.Command("ufw", "allow", direction, "on", secureInterface)
	err := cmd.Run()
	if err != nil {
		log.Println("Firewall Allow Interface Error: ", err)
	}
}

func AllowIPPortInterface(targetIP, targetPort, vulInterface string) {
	cmd := exec.Command("ufw", "allow", "in", "on", vulInterface, "to", targetIP, "port", targetPort)
	err := cmd.Run()
	if err != nil {
		log.Println("Firewall Configuration Error: ", err)
	}
}

func AllowForwardInterface(secureInterface, vulInterface string) {
	cmd := exec.Command("ufw", "route", "allow", "in", "on", secureInterface, "out", "on", vulInterface)
	err := cmd.Run()
	if err != nil {
		log.Println("Firewall Allow Forward Interface Error: ", err)
	}
}

func AllowForwardInterfacePort(srcInterface, port string) {
	cmd := exec.Command("ufw", "route", "allow", "in", "on", srcInterface, "to", "any", "port", port)
	err := cmd.Run()
	if err != nil {
		log.Println("Firewall Allow Forward Interface Error: ", err)
	}
}

func AddDefaultGateway(gatewayIP string) {
	cmd := exec.Command("route", "add", "default", "gw", gatewayIP)
	err := cmd.Run()
	if err != nil {
		log.Println("Firewall Add Default Gateway Error: ", err)
	}
}

func DenySrcIPInterface(targetIP, vulInterface string) {
	cmd := exec.Command("ufw", "deny", "in", "on", vulInterface, "from", targetIP)
	err := cmd.Run()
	if err != nil {
		log.Println("Firewall Configuration Error: ", err)
	}
}

func AllowSrcIPPortInterface(sourceIP, targetIP, targetPort, vulInterface string) {
	cmd := exec.Command("ufw", "allow", "in", "on", vulInterface, "from", sourceIP, "to", targetIP, "port", targetPort)
	err := cmd.Run()
	if err != nil {
		log.Println("Firewall Configuration Error: ", err)
	}
}

func AllowSrcIPPort(sourceIP, targetIP, targetPort string) {
	cmd := exec.Command("ufw", "allow", "in", "from", sourceIP, "to", targetIP, "port", targetPort)
	err := cmd.Run()
	if err != nil {
		log.Println("Firewall Configuration Error: ", err)
	}
}
