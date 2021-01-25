
import sys
import time 
import argparse
import pandas as pd

from pyModbusTCP.client import ModbusClient

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

# Registers #0-#1440
Number_of_Measurements = 1441 
# First N rows of dataframe 
# Maxium: 1440 for this dataset

SERVER_HOST = "192.168.10.15"
SERVER_PORT = 502

c = ModbusClient()
# c.debug(True) # uncomment this line to see debug message

# define modbus server host, port
c.host(SERVER_HOST)
c.port(SERVER_PORT)

#my_list = list(range(15)) #used for debugging when there is no PV data
#print(my_list)

#Reading PV data from file
#dataset = pd.read_csv('EPRI_PV_Data_10_Measurements.csv', delimiter=',')        # incomplete dataset
#dataset = pd.read_csv('EPRI_PV_Data_24_Hours_at_1_Min_Test.csv', delimiter=',') # incomplete dataset
dataset = pd.read_csv('EPRI_PV_Data_24_Hours_at_1_Min.csv', delimiter=',')       # full dataset
print("Reading CSV File...")
dataset.columns = ['Time','KW'] # renaming the data frame columns
index = dataset.index 
columns = dataset.columns
#print(index)
#print(columns)
hourValues = dataset[['Time']] # includes index
newDataset = dataset.iloc[0:Number_of_Measurements] 
print(newDataset.index)
#print(newDataset.values)
PV_KW_list = newDataset['KW'].tolist() #extracting list out of the values column
del PV_KW_list[-1] #deleting last item cause it is NaN
PV_KW_list = [ int(x) for x in PV_KW_list ] #converting into a list of integers
#print(PV_KW_list) # used for debugging
#print(str(len(PV_KW_list)))

# open or reconnect TCP to server
if not c.is_open():
    if not c.open():
        print("Unable to connect to "+SERVER_HOST+":"+str(SERVER_PORT))

# if open() is ok, write the registers with the PV generation values
if c.is_open():
    print("Database Client Connected to Server")
    #list_int = c.read_input_registers(0, (len(PV_KW_list)-1))  
    list_int = c.read_input_registers(0, len(PV_KW_list))
    if list_int:
        print("Registers addresses #0 to #"+str(len(PV_KW_list))+": "+str(list_int))
    for addr in range(len(PV_KW_list)):
        is_ok = c.write_single_register(addr, PV_KW_list[addr]) 
        if is_ok:
            print("register #" + str(addr) + ": write [PV gen (KW)] to " + str(PV_KW_list[addr]))
        else:
            print("resgister #" + str(addr) + ": unable to write " + str(PV_KW_list[addr]))
    print("Finish writing "+ str(addr+1) +" resgisters with PV data measurements")    
# closing TCP connection after writing all registers
c.close()
