
import sys
import time
import argparse
import pandas as pd

from pyModbusTCP.client import ModbusClient

# PV Data from EPRI -  Distributed PV Monitoring and Feeder Analysis
# https://dpv.epri.com/measurement_data.html
# 1 minute resolution PV generation data 
# Unit: kW
# Recording time: 24 hours
# Data points: 1440

# ModuleOT Testbed Version 1
# July 31, 2019
# [PV Dataset]<----[Modbus Database Client]----->[Modbus Sever]<-------[Modbus Client]
#            (Read)                       (Write)               (Read)

# Registers #0-#1440
Number_of_Measurements = 1441
# First N rows of dataframe 
# Maxium: 1440 for this dataset
Number_of_Readings = Number_of_Measurements
Sampling_Rate = 1 #in seconds

#SERVER_HOST = "localhost"
#SERVER_HOST = "169.254.164.20"
#SERVER_PORT = 504
SERVER_HOST = "192.168.10.15"
SERVER_PORT = 502

c = ModbusClient()

#my_list = list(range(15)) 
#print(my_list)

#dataset = pd.read_csv('EPRI_PV_Data_10_Measurements.csv', delimiter=',')
#dataset = pd.read_csv('EPRI_PV_Data_24_Hours_at_1_Min_Test.csv', delimiter=',')
dataset = pd.read_csv('EPRI_PV_Data_24_Hours_at_1_Min.csv', delimiter=',')
print("Reading CSV File...")
dataset.columns = ['Time','KW'] # renaming the data frame columns
index = dataset.index 
columns = dataset.columns
#print(index)
#print(columns)

hourValues = dataset[['Time']] # includes index
newDataset = dataset.iloc[0:Number_of_Readings] # first N rows of dataframe
print(newDataset.index)
#print(newDataset.values)
PV_KW_list = newDataset['KW'].tolist() #extracting list out of the values column
del PV_KW_list[-1] #deleting last item cause it is NaN
PV_KW_list = [ int(x) for x in PV_KW_list ] #converting into integers
#print(PV_KW_list)

# uncomment this line to see debug message
# c.debug(True)

# define modbus server host, port
c.host(SERVER_HOST)
c.port(SERVER_PORT)

# open or reconnect TCP to server
if not c.is_open():
    if not c.open():
        print("Unable to connect to "+SERVER_HOST+":"+str(SERVER_PORT))

# if open() is ok, write the registers with the PV generation values
if c.is_open():
    print("Connected to Server")
    for addr in range(len(PV_KW_list)):
        is_ok = c.read_input_registers(addr, 1) 
        if is_ok:
            print("register #" + str(addr) + ": PV gen (KW) :" + str(is_ok))
        else:
            print("resgister #" + str(addr) + ": Unable to read " + str(PV_KW_list[addr]))
        time.sleep(Sampling_Rate)
# closing TCP connection after writing all registers
print("Finish reading registers")   
c.close()

