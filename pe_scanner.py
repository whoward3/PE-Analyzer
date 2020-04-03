"""
pe_scanner
Description: A basic python script to scan through a directory of files and create a report of all those files
Authors: Winston Howard, Alice Blair, Chance Sweetser
Created Date: 02/18/20
"""
import subprocess
import pefile
import peutils
import os


def scanner():
    """
    The scanner function used to scan directory of files
    """
       path = input('Path to PE File Directory: ')
        for filename in os.listdir(path):
        print("\n {} : \r".format(filename))
        try:
            pe = pefile.PE(path+filename)
            print("PASS\n")
            
            # This hashes stuff, but I am not sure what actually needs to get hashed inorder to get the desired hash
            # I tried encoding the pe variable but that did not work

            str = filename
            result = hashlib.md5(str.encode())
            print (result.hexdigest())

            # This dumps all of the info to ther terminal about the pe file
            # print (pe.dump_info())
            info = pe.dump_info()
            m = re.findall('(?<=DllCharacteristics: )[A-Za-z_,]+\t*.[^0x\n]*', info)
            print (m[0])
        except Exception:
            print("FAILED")


def reporter(pe):
    """
    The reporter function that will return a report including a reference to virus total via:
    https://www.virustotal.com/gui/search/{HASH}
    """

    pass


# C:\Program Files (x86)\Steam\steamapps\common\Star Wars Empire at War\corruption\
scanner()
