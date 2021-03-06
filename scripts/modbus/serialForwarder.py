#!/usr/bin/env python
"""
Pymodbus Synchronous Serial Forwarder
--------------------------------------------------------------------------

We basically set the context for the tcp serial server to be that of a
serial client! This is just an example of how clever you can be with
the data context (basically anything can become a modbus device).
"""
# --------------------------------------------------------------------------- # 
# import the various server implementations
# --------------------------------------------------------------------------- # 
from pymodbus.server.sync import StartTcpServer as StartServer
from pymodbus.client.sync import ModbusSerialClient as ModbusClient

from pymodbus.datastore.remote import RemoteSlaveContext
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext
import argparse
import json
# --------------------------------------------------------------------------- # 
# configure the service logging
# --------------------------------------------------------------------------- # 
#import logging
#logging.basicConfig()
#log = logging.getLogger()
#log.setLevel(logging.DEBUG)


def run_serial_forwarder(modbusip):
    # ----------------------------------------------------------------------- #
    # initialize the datastore(serial client)
    # ----------------------------------------------------------------------- #
    client = ModbusClient(method='binary', port='/dev/ttyUSB0')
    store = RemoteSlaveContext(client)
    context = ModbusServerContext(slaves=store, single=True)

    # ----------------------------------------------------------------------- #
    # run the server you want
    # ----------------------------------------------------------------------- #
    StartServer(context, address=(modbusip, 502))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-ip', '--IP', type=str, default='localhost', help='IP Address')
    args = parser.parse_args()
    with open("/etc/moduleot/config.json", "r") as f:
        data = f.read()
        datastore = json.loads(data)
    run_serial_forwarder(IP)
