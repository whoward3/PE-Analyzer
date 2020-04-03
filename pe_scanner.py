"""
pe_scanner
Description: A basic python script to scan through a directory of files and create a report of all those files
Authors: Winston Howard, Sam "Alice" Blair, Chance Sweetser
Created Date: 02/18/20
"""
import subprocess
import pefile
import peutils
import os
import webbrowser
import re
import hashlib


def scanner():
    """
    The scanner function used to scan directory of files
    """
    path = input('Path to PE File Directory: ')
    for filename in os.listdir(path):
        print("\n {} : \r".format(filename))
        listOfFiles = []
        try:
            pe = pefile.PE(path+filename)
            print("PASS\n")
            
            # This hashes stuff, but I am not sure what actually needs to get hashed inorder to get the desired hash
            # I tried encoding the pe variable but that did not work
            
            
            str = filename
            result = hashlib.md5(str.encode())
            print (result.hexdigest())


            info = pe.dump_info()
            #print(info) #DUMPS ALL INFO
            
            dll_grabber = re.findall('[A-Za-z0-9]*.dll[\.A-Za-z0-9]*', info)
            print (dll_grabber) # this is all of the referernces to dll in a pe file

            number = len(dll_grabber)
            packed = "" #This will be for if it is packed
            if (number < 10):
                packed = "Is Packed"
            else:
                packed = "Is not Packed"



            dll_characteristics = re.findall('(?<=DllCharacteristics: )[A-Za-z_,]+\t*.[^0x\n]*', info)
            print (dll_characteristics[0]) #This is the DLL Charcteristics for num 5
            
            date = re.findall('(?<=TimeDateStamp:                 ............)[A-Za-z0-9: ]*', info)
            print (date[0]) #This is the compile time
            
            file = PE_File(result, date, packed, dll_grabber, dll_characteristics, "IDC") 
            listOfFiles.append(file)
        except Exception:
            print("FAILED")

   # reporter(listOfFiles)


def reporter(pe):
    """
    The reporter function that will return a report including a reference to virus total via:
    https://www.virustotal.com/gui/search/{HASH}
    """
    with open('report_template.html', 'r') as report_template:
        data = report_template.read()

        # Inflate Q1
        data = data.replace("[Q1]", Q1)

        f = open("report.html", "w")
        f.write(data)
        f.close()

    webbrowser.open_new_tab('report.html')


class PE_File(object):
    md5_hash = ""
    compile_date = ""
    obfuscation = ""
    imports = ""
    host_indicators = ""
    network_indicators = ""
    purpose = ""

    def __init__(self, md5_hash, compile_date, obfuscation, imports, host_indicators, network_indicators, purpose):
        md5_hash = self.md5_hash
        compile_date = self.compile_date
        obfuscation = self.obfuscation
        imports = self.imports
        host_indicators = self.host_indicators
        network_indicators = self.network_indicators
        purpose = self.purpose


reporter("Q1")
