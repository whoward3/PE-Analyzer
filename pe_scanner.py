"""
pe_scanner
Description: A basic python script to scan through a directory of files and create a report of all those files
Author: Winston Howard
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
            print(pe)
        except Exception:
            print("FAILED")


def reporter(pe):
    """
    The reporter function that will return a report including a reference to virus total via:
    https://www.virustotal.com/gui/search/{HASH}
    """
    pass


scanner()
