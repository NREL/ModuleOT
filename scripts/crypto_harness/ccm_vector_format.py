################################################################################
#####CCM-DVPT 128 192 256
########################################
#####::Given Parameters::
#####[Alen, Plen, Nlen, Tlen] []-means it changes
#####Key
#####Count
#####Nonce
#####Adata
#####CT
#####::Return Parameters::
####Result (Pass/Fail)
####Payload
################################################################################

################################################################################
#####CCM-VADT 128 192 256
########################################
#####::Given Parameters::
#####[Alen], Plen, Nlen, Tlen
#####Key
#####Count
#####Nonce
#####Adata
#####Payload
#####::Return Parameters::
####CT
################################################################################

################################################################################
#####CCM-VNT 128 192 256
########################################
#####::Given Parameters::
#####Alen, Plen, [Nlen], Tlen
#####Key
#####Count
#####Nonce
#####Adata
#####Payload
#####::Return Parameters::
####CT
################################################################################

################################################################################
#####CCM-VPT 128 192 256
########################################
#####::Given Parameters::
#####Alen, [Plen], Nlen, Tlen
#####Key
#####Count
#####Nonce
#####Adata
#####Payload
#####::Return Parameters::
####CT
################################################################################

import os
CipherOutputFile= open("CCM_CipherTest.txt", "w+")
CipherFileList = []

##Values needed for Validation Output
Title       = ""
Cipher      = ""
Key         = ""
Operation   = ""
Plaintext   = ""
Ciphertext  = ""

CipherOutputFile.write("#Leidos Verification AES\n\n")

for file in os.listdir("."):
    if file.endswith(".req"):
        CipherFileList.append(file)
        

for TestFile in CipherFileList:
    TestFileP = open(TestFile, "r")           #FilePointer
    Title  = "Title = "+TestFile+"\n" #Print out Cipher
    #CipherOutputFile.write(Title)
    for line in TestFileP:                    #Read through
        if (line.find("COUNT") != -1):
            Count = "Count ="+line.split('=')[1]
        if (line.find('ENCRYPT') != -1):              #Operation
            Operation = "Operation = ENCRYPT\n"
        if (line.find("Key Length") != -1):
            KeyLength = line.split(':')
            KeyLength = filter(str.isdigit,KeyLength[1])
            Cipher = "Cipher = AES-"+KeyLength+"-ECB\n"
        if (line.find("KEY") != -1):
            KeyValue = "Key ="+line.split('=')[1]
            CipherOutputFile.write(Title)
            CipherOutputFile.write(Count)
            CipherOutputFile.write(Cipher)
            CipherOutputFile.write(KeyValue)
            CipherOutputFile.write(Operation)
        if (line.find("PLAINTEXT") != -1):
            Plaintext = "Plaintext ="+line.split('=')[1]
            CipherOutputFile.write(Plaintext)
        if (line.find("CIPHERTEXT") != -1):
            Ciphertext= "Ciphertext ="+line.split('=')[1]
            CipherOutputFile.write(Ciphertext)
            CipherOutputFile.write("\n")
        #if (line.find('COUNT') != -1):               #New Cipher
        #    print(line)  
    TestFileP.close()
#onlyfiles = os.listdir("./")
#print(onlyfiles[4])
#CipherTestFile.write(str(onlyfiles))
CipherOutputFile.close()
