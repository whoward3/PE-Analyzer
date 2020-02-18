"""
pe_scanner
Description: A basic python script to scan through a directory of files and create a report of all those files
Author: Winston Howard
Created Date: 02/18/20
"""
import subprocess
import pefile
import os


def scanner():
    """
    The scanner function used to scan directory of files
    """
    path = input('Path to PE File Directory: ')
    for filename in os.listdir(path):
        print(filename)
        pe = pefile.PE(filename)
        print(pe)
    pass


scanner()
