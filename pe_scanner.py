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
        try:
            pe = pefile.PE(path+filename)
            print("PASS\n")

            # This hashes stuff, but I am not sure what actually needs to get hashed inorder to get the desired hash
            # I tried encoding the pe variable but that did not work

            str = filename
            result = hashlib.md5(str.encode())
            print(result.hexdigest())

            # This dumps all of the info to ther terminal about the pe file
            # print (pe.dump_info())
            info = pe.dump_info()
            m = re.findall(
                '(?<=DllCharacteristics: )[A-Za-z_,]+\t*.[^0x\n]*', info)
            print(m[0])
        except Exception:
            print("FAILED")


def reporter(fileList):
    """
    The reporter function that will return a report including a reference to virus total via:
    https://www.virustotal.com/gui/search/{HASH}
    """
    with open('report_template.html', 'r') as report_template:
        html_template = report_template.read()

    with open('report_section.html', 'r') as report_section:
        html_section = report_section.read()

        file_section = ""
        for f in fileList:
            data = html_section
            data = data.replace("[FILE NAME]", f.name)

            # Q1
            uri = "https://www.virustotal.com/gui/search/"+f.md5_hash
            data = data.replace("[Q1]", uri)

            # Q2
            data = data.replace("[Q2]", f.compile_date)

            # Q3
            data = data.replace("[Q3]", f.obfuscation)

            # Q4
            data = data.replace("[Q4]", f.imports)

            # Q5
            data = data.replace("[Q5]", f.host_indicators)

            # Q6
            data = data.replace("[Q6]", f.network_indicators)
            file_section = file_section + "\n" + data
        report = html_template.replace("[FILE SECTION]", file_section)

        f = open("report.html", "w")
        f.write(report)
        f.close()

    webbrowser.open_new_tab('report.html')


class PE_File(object):
    md5_hash = ""
    compile_date = ""
    obfuscation = ""
    imports = ""
    host_indicators = ""
    network_indicators = ""
    name = ""

    def __init__(self, md5_hash, compile_date, obfuscation, imports, host_indicators, network_indicators, name):
        md5_hash = self.md5_hash
        compile_date = self.compile_date
        obfuscation = self.obfuscation
        imports = self.imports
        host_indicators = self.host_indicators
        network_indicators = self.network_indicators
        name = self.name


scanner()
