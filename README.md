# ModuleOT
ModuleOT is an open hardware security platform which provides all features necessary for securing remote energy resources. 
The platform consists of a physical bump in-the wire device which runs a custom-built application built with Go and Python and leverages AES-NI Instruction set available on modern hardware for cryptographic acceleration. By combining these features, ModuleOT acts as an all-in-one low-cost solution to enable cryptographically secured communications to any critical remote servers or devices. Because the software application has been built using Golang, this source can be easily compiled for different hardware platforms.
The module is designed to provide the following core features:
* Encrypted communications across an untrusted network
* Certificate-based authentication with secure storage
* Hardware cryptographic acceleration
* IP-based whitelisting
* Local firewall management
* Legacy (RS485) device support

## Getting Started

These instructions will get you a copy of the project up and running on your local machine. To locally compile the source code, you will need to set up Golang on your system and compile the code with the included dependancy packages in your $GOPATH/src directory

### Dependencies

* [Python](https://www.python.org/) - Interpreted programming language  

* [Nmap](https://nmap.org/) - Network mapping utility

* [OpenSSL](https://www.openssl.org/) - TLS/SSL communciation handler

* [OpenSSH](https://www.openssh.com/) - SSH server handler

* [Pip](https://pypi.org/project/pip/) - Python package installer

* [PyModbusTCP](https://pymodbustcp.readthedocs.io/en/latest/) - Python based ModbusTCP-Serial Relay 


### Installing

1. Install Python
```
sudo apt-get install python
```
2. Install Nmap
```
sudo apt-get install nmap
```
3. Install OpenSSL
```
sudo apt-get install openssl
```
4. Install OpenSSH
```
sudo apt-get install openssh-server
```
5. Configure SSH Server
```
sudo nano /etc/ssh/sshd_config
``` 
6. Install Pip
```
sudo apt-get install python-pip
```
7. Install PyModbusTCP
```
sudo pip install PyModbusTCP
```
8. Place the MotApp executable in /usr/bin/
9. Place the moduleot.service file in /etc/services/ and enable the service
```
sudo systemctl enable moduleot.service
```

## Deployment

A ModuleOT device may be easily configured and deployed using any computer system running a Debian-based Linux OS. To do so, The system dependancies must be installed   

### The Config File 
The configuration file for the ModuleOT application is located at /usr/lib/ssl/config.json
An example configuration for a ModuleOT device is shown below:
Note: The MODBUSIP field only has to be set for Modbus serial devices:
```
{
    "WANINTERFACE": "enp1s0",
    "WANIP": "10.10.49.45",
    "WANMASK": "24",
    "LANINTERFACE": "enp2s0",
    "LANIP": "192.168.10.10",
    "LANMASK": "24",
    "TLS_PORT": "8000",
    "WHITELIST" : ["192.168.10.20","192.168.10.30","192.168.10.40","192.168.10.10","10.10.49.45","10.10.49.49"],
    "MODBUSIP": "192.168.10.40",
    "NETWHITELIST": ["192.168.10.10","192.168.10.40”, “192.168.10.30", “192.168.10.20”, “192.168.10.10”],
    "PORTS": [“502", “443”, “80”, "20000"],
 
 
}
```
*Note: Always remember to restart moduleot.service after changing the config file!*


### Default Configuration
By default, the IP address of the device is:
* 10.10.49.45/24 on the server device
* 10.10.49.49/24 on the client device

### User Access Control
ModuleOT has the following user account configuration by default:
Username	Password	Privileges
motuser	    motpass	    SSH-login, basic rights
moduleot    NREL	    Read-write, sudo
root	    NREL	    Administrator

*Note: Due to this design only the motuser account may login via ssh and it is necessary to run a “su” command to switch users to a more privileged account*

## Built With

* [Golang](https://golang.org/) - Open source, compiled programming language with strong multithreading and communication support
* [Protobuf](https://developers.google.com/protocol-buffers/) - Used to serialize/deserialize data


## Versioning

We use [Semantic Versioning](http://semver.org/). For the versions available, see the [tags on this repository](https://github.nrel.gov/ahasandk/moduleOT/tags). 


## NOTICE

Notice: This computer software was prepared Alliance for Sustainable Energy, LLC, hereinafter the Contractor, under Contract DE-AC36-08GO28308 with the Department of Energy (DOE). All rights in the computer software are reserved by DOE on behalf of the United States Government and the Contractor as provided in the Contract. You are authorized to use this computer software for Governmental purposes but it is not to be released or distributed to the public. NEITHER THE GOVERNMENT NOR THE CONTRACTOR MAKES ANY WARRANTY, EXPRESS OR IMPLIED, OR ASSUMES ANY LIABILITY FOR THE USE OF THIS SOFTWARE. This notice including this sentence must appear on any copies of this computer software.

NOTICE: EXPORT OR DEEMED EXPORT OF THIS SOFTWARE MAY VIOLATE U.S. EXPORT CONTROLS. DO NOT PROVIDE THIS SOFTWARE (OR ACCESS TO THIS SOFTWARE) TO ANY NON-U.S. CITIZEN WITHOUT PROPER AUTHORIZATION. ALLIANCE WILL NOT BE RESPONSIBLE FOR ANY VIOLATION OF EXPORT CONTROL BY ANY OTHER PARTY.






 


