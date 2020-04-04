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
    print("Log: ")
    for filename in os.listdir(path):
        print("\n {} : \r".format(filename))
        try:
            pe = pefile.PE(path+filename)
            print("PASS\n")

            # Get md5 hash
            file_hash = hashlib.md5(filename.encode()).hexdigest()

            # Get the PE Data
            pe_data = pe.dump_info()

            # Get Imports
            file_imports = re.findall(
                '[A-Za-z0-9]*.dll[\.A-Za-z0-9]*', pe_data)

            # Get Obfuscation
            if (len(file_imports) < 10):
                file_obfuscation = "It is packed and obfuscated."
            else:
                file_obfuscation = "It is not obfuscated or packed."

            # Get Host Indicators
            file_host_indicators = re.findall(
                '(?<=DllCharacteristics: )[A-Za-z_,]+\t*.[^0x\n]*', pe_data)

            # Get Compile Date
            file_compile_date = re.findall(
                '(?<=TimeDateStamp:                 ............)[A-Za-z0-9: ]*', pe_data)

            # Get Network Indicators
            file_network_indicators = re.findall(
                '(?<![-\.\d])(?:0{0,2}?[0-9]\.|1\d?\d?\.|2[0-5]?[0-5]?\.){3}(?:0{0,2}?[0-9]|1\d?\d?|2[0-5]?[0-5]?)(?![\.\d])', pe_data)

            # Edge Cases
            if(not file_compile_date):
                file_compile_date.append("The compiled date is unknown.")
            if(not file_imports):
                file_imports.append(
                    "PE Analyser was unable to find any imports.")
            if(not file_host_indicators):
                file_host_indicators.append(
                    "PE Analyser was unable to find any host indicators.")
            if(not file_network_indicators):
                file_network_indicators.append(
                    "PE Analyser was unable to find any network indicators.")

            pe_file = PE_File(str(file_hash), str(file_compile_date[0]), file_obfuscation, str(file_imports),
                              str(file_host_indicators), str(file_network_indicators), filename)

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
