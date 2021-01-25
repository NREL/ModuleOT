# Modbus/TCP server with start/stop schedule

import argparse
import time
from pyModbusTCP.server import ModbusServer, DataBank
# need https://github.com/dbader/schedule
#import schedule

# PV Data from EPRI -  Distributed PV Monitoring and Feeder Analysis
# https://dpv.epri.com/measurement_data.html
# Filetype: .CSV
# 1 minute resolution PV generation dataset 
# Unit: kW
# Recording time: 24 hours
# Data points: 1440

# ModuleOT Testbed Version 1
# July 31, 2019

# [PV Dataset]<----[Modbus Database Client]----->[Modbus Sever]<-------[Modbus Client]
#            (Read)                       (Write)               (Read)     

SERVER_HOST = "192.168.10.15"
SERVER_PORT = 502

if __name__ == "__main__":
    # parse args
    parser = argparse.ArgumentParser() 
    parser.add_argument("-H", "--host", type=str, default=SERVER_HOST, help="Host")
    parser.add_argument("-p", "--port", type=int, default=SERVER_PORT, help="TCP port")
    args = parser.parse_args()
    # init modbus server and start it
    server = ModbusServer(host=args.host, port=args.port, no_block=True)
    server.start()
    # main loop
    while True:
        time.sleep(1)
    server.stop()
