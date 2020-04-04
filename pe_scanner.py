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

class PE_File(object):
    _md5_hash = ""
    _compile_date = ""
    _obfuscation = ""
    _imports = ""
    _host_indicators = ""
    _network_indicators = ""
    _name = ""

    def __init__(self, md5_hash, compile_date, obfuscation, imports, host_indicators, network_indicators, name):
        self._md5_hash = md5_hash
        self._compile_date = compile_date
        self._obfuscation = obfuscation
        self._imports = imports
        self._host_indicators = host_indicators
        self._network_indicators = network_indicators
        self._name = name

def scanner():
    """
    The scanner function used to scan directory of files
    """
    path = input('Path to PE File Directory: ')
    file_list = []
    for filename in os.listdir(path):
        print("\n {} : \r".format(filename))
        try:
            pe = pefile.PE(path+filename)
            print("PASS\n")

            # This hashes stuff, but I am not sure what actually needs to get hashed inorder to get the desired hash
            # I tried encoding the pe variable but that did not work

            file_obj = open(os.path.join(path, filename), 'rb')
            print (file_obj)
            data = file_obj.read()
            noGod = hashlib.md5(data)
            f_hash =  noGod.hexdigest()
            # print(result.hexdigest())

            info = pe.dump_info()
            # print(info) #DUMPS ALL INFO

            dll_grabber = re.findall('[A-Za-z0-9]*.dll[\.A-Za-z0-9]*', info)
            # this is all of the referernces to dll in a pe file
            # print(dll_grabber)

            number = len(dll_grabber)
            packed = ""  # This will be for if it is packed
            if (number < 10):
                packed = "It is packed and obfuscated."
            else:
                packed = "It is not obfuscated or packed."

            dll_characteristics = re.findall(
                '(?<=DllCharacteristics: )[A-Za-z_,]+\t*.[^0x\n]*', info)
            # This is the DLL Charcteristics for num 5
            # print(dll_characteristics[0])

            date = re.findall(
                '(?<=TimeDateStamp:                 ............)[A-Za-z0-9: ]*', info)
            # print(date[0])  # This is the compile time

            network = re.findall('(?<![-\.\d])(?:0{0,2}?[0-9]\.|1\d?\d?\.|2[0-5]?[0-5]?\.){3}(?:0{0,2}?[0-9]|1\d?\d?|2[0-5]?[0-5]?)(?![\.\d])', info)

            pe_file = PE_File(str(f_hash), str(date[0]), packed, str(dll_grabber),
                           str(dll_characteristics), str(network), filename)


            file_list.append(pe_file)
        except Exception:
            print("FAILED")

    reporter(file_list)


def reporter(file_list):
    """
    The reporter function that will return a report including a reference to virus total via:
    https://www.virustotal.com/gui/search/{HASH}
    """
    with open('report_template.html', 'r') as report_template:
        html_template = report_template.read()

    with open('report_section.html', 'r') as report_section:
        html_section = report_section.read()

        file_section = ""
        for f in file_list:
            data = html_section
            data = data.replace("[FILE NAME]", f._name)

            # Q1
            uri = "https://www.virustotal.com/gui/search/"+f._md5_hash
            data = data.replace("[Q1]", uri)

            # Q2
            data = data.replace("[Q2]", f._compile_date)

            # Q3
            data = data.replace("[Q3]", f._obfuscation)

            # Q4
            data = data.replace("[Q4]", f._imports)

            # Q5
            data = data.replace("[Q5]", f._host_indicators)

            # Q6
            data = data.replace("[Q6]", f._network_indicators)
            file_section = file_section + "\n" + data

        if(file_section == ""):
         file_section = """<p>PE Analyser found no valid PE files to scan. Please ensure you provide PE Analyser a path to a directory not a path to a specific file
                           and that the PE files in the specified directory are compatabile with Pefile by Ero Carrera.</p>"""

        report = html_template.replace("[FILES SECTION]", file_section)
        report = report.replace("[FILES]", str(len(file_list)))

        f = open("report.html", "w")
        f.write(report)
        f.close()

    webbrowser.open_new_tab('report.html')


scanner()
