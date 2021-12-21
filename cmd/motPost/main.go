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

package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"golang.org/x/crypto/sha3"
)

const (
	OMV1       = 1
	OMV2       = 1
	OMV3       = 1
	OMV1STRING = "1"
	OMV2STRING = "1"
	OMV3STRING = "1"
)

func commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

func ensureDir(dir string) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0755)
		if err != nil {
			panic(err)
		}
	}
}

func checkFileHash() {
	//Verify hash of executable
	file, _ := ioutil.ReadFile("/etc/moduleot/Hashfile")
	correctHashString := strings.TrimSpace(string(file))
	file, _ = ioutil.ReadFile("/usr/bin/motApp")
	hash := sha3.Sum256(file)
	hashString := fmt.Sprintf("%x", hash)
	if hashString != correctHashString {
		log.Println("Incorrect firmware Hash provided Correct Hash: ", hashString)
		//log.Println("looking for: ", correctHashString)
	}else
	{
		log.Println("Firmware Integrity Verified")
	}
}

func main() {

	// Build commands
	restartCmd := exec.Command("systemctl", "restart", "moduleot")

	// Ensure directory exists
	ensureDir("/var/log")

	// Configure Logging
	logfile, err := os.OpenFile("/var/log/moduleot/POST_"+time.Now().String()[:28]+".log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer logfile.Close()
	log.SetOutput(logfile)

	checkFileHash()

	// check if nmap exists
	if commandExists("nmap") {
		log.Println("nmap Exists")
	} else {
		log.Fatalln("nmap not found")
	}

	// check if python exists
	if commandExists("python") {
		log.Println("python Exists")
	} else {
		log.Fatalln("python not found")
	}

	// check if openssl exists
	if commandExists("openssl") {
		log.Println("openssl Exists")
	} else {
		log.Fatalln("openssl not found")
	}

	// check openssl version
	out, err := exec.Command("openssl", "version").Output()
	if err != nil {
		log.Fatalln("unable to run command: openssl version")
	} else {
		re := regexp.MustCompile("OpenSSL (\\d*).(\\d*).(\\d*)\\w?")
		match := re.FindStringSubmatch(string(out))
		log.Println("Found OpenSSL version ", string(out))
		if len(match) > 0 {
			version1, _ := strconv.Atoi(match[1])
			version2, _ := strconv.Atoi(match[2])
			version3, _ := strconv.Atoi(match[3])
			if version1 < OMV1 {
				log.Fatalln("minimum openssl version required: " + OMV1STRING + "." + OMV2STRING + "." + OMV3STRING)
			} else {
				if version2 < OMV2 {
					log.Fatalln("minimum openssl version required: " + OMV1STRING + "." + OMV2STRING + "." + OMV3STRING)
				} else {
					if version3 < OMV3 {
						log.Fatalln("minimum openssl version required: " + OMV1STRING + "." + OMV2STRING + "." + OMV3STRING)
					}
				}
			}
			log.Println("OpenSSL version is sufficient")
		} else {
			log.Fatalln("Unable to get openssl version ")
		}
	}
	log.Println("ModuleOT Application POST successful. Starting firmware integrity check service")

	// Start File watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()
	err = watcher.Add("/usr/bin")
	err = watcher.Add("/etc/moduleot")

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			//log.Println("event:", event)
			if event.Op&fsnotify.Write == fsnotify.Write {
				if event.Name == "/etc/moduleot/config.json" {
					log.Println("Modified config file:", event.Name)
					log.Println("Restarting moduleot service...")
					restartCmd.Start()
					log.Println("Moduleot service restarted")
				} else {
					if !(strings.Contains(event.Name, ".swp")) {
						log.Fatalln("Modified file:", event.Name)
					}
				}

			}
			if event.Op&fsnotify.Write == fsnotify.Remove {
				if event.Name == "/etc/moduleot/config.json" {
					log.Fatalln("Removed config file:", event.Name)
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Println("File watcher error:", err)
		}
	}
}
