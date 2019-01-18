#!/usr/bin/python
import json,xmltodict
import sys,os,re,json
from commands import getoutput

class colortext:
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    OKYellow = '\033[33m'
    OKLight = '\033[96m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

if len(sys.argv) == 1:
        print '\n'
        print colortext.OKBLUE + "Quick Tool To Analysis Nmap Output by : WazeHell \n" + colortext.ENDC
        print colortext.FAIL + 'Usage: %s <nmapoutputdir>' % sys.argv[0] + colortext.ENDC
        print '\n'
        sys.exit(1)

if not os.path.exists(sys.argv[1]):
    print colortext.FAIL + '[-] not found ! %s' % sys.argv[1] + colortext.ENDC
    sys.exit(1)

def getexploits(ob):
    command = "searchsploit --nmap {} -j".format(ob)
    out = getoutput(command)
    try:
        search = re.search('{(.*)}', out)
        result = search.group(0)
    except:
        result = False
    if result:
        ss = json.loads(result)
        print(colortext.OKGREEN)
        print("[+] Title : " + ss['Title'])
        print("     [+] Date : " + ss['Date'])
        print("     [+] Platform : " + ss['Platform'])
        print("     [+] Type : " + ss['Type'])
        print(colortext.ENDC)
    else:
        print colortext.FAIL + '[-] No Public Exploits Found In ! %s' % ob + colortext.ENDC


    pass

def searchsploirtcheck():
    s = getoutput("which searchsploit")
    if 'searchsploit' in s:
        return True
    else:
        return False

def returnerror():
    return False

def xml2json(xml):
    try:
        xmlfile = open(xml)
        xml_content = xmlfile.read()
        xmlfile.close()
        xmljson = json.dumps(xmltodict.parse(xml_content), indent=4, sort_keys=True)
        jsondata = json.loads(xmljson)
        return jsondata
    except:
        returnerror()

def getports(ob):
    try:
        ports = ob['nmaprun']['host']['ports']['port']
        return ports
    except:
        returnerror()

def getstatus(ob):
    try:
        hostnum = ob['nmaprun']['runstats']['hosts']['@total']
        scanned = ob['nmaprun']['runstats']['hosts']['@up']
        stat = {'hosts':hostnum,'scanned':scanned}
        return stat
    except:
        returnerror()

def ser_analysis(ob):
    try:
        print(colortext.OKLight)
        print("     [+] Servies Name : " + ob['@name'])
        if ob['@version']:
            print("     [+] Servies Version : " + ob['@version'])
        if ob['@product']:
            print("     [+] Servies Product : " + ob['@product'])
        if ob['@tunnel']:
            print("     [+] Servies tunnel : " + ob['@tunnel'])
        if ob['@extrainfo']:
            print("     [+] Servies Extrainfo : " + ob['@extrainfo'])
        print(colortext.ENDC)
    except:
        returnerror()

def port_analysis(port):
    try:
        if port['state']['@state'] == 'open':
            print(colortext.OKGREEN)
            print("[+] Port Number : " + port['@portid'])
            print("     [+] Status : " + port['state']['@state'])
            print("     [+] Reason : " + port['state']['@reason'])
            print("     [+] TTL : " + port['state']['@reason_ttl'])
            print(colortext.ENDC)
        else:
            print(colortext.OKBLUE)
            print("[+] Port Number : " + port['@portid'])
            print("     [+] Status : " + port['state']['@state'])
            print("     [+] Reason : " + port['state']['@reason'])
            print("     [+] TTL : " + port['state']['@reason_ttl'])
            print(colortext.ENDC)
        try:
            if port['state']['@state'] == 'open':
                services = ser_analysis(port['service'])
        except:
            pass

        return True
    except:
        returnerror()


def port_analysis2(port):
    try:
        if port['state']['@state'] == 'open':
            print(colortext.OKGREEN)
            print("[+] Port Number : " + port['@portid'])
            print("     [+] Status : " + port['state']['@state'])
            print("     [+] Reason : " + port['state']['@reason'])
            print("     [+] TTL : " + port['state']['@reason_ttl'])
            print(colortext.ENDC)
        else:
            print(colortext.OKBLUE)
            print("[+] Port Number : " + port['@portid'])
            print("     [+] Status : " + port['state']['@state'])
            print("     [+] Reason : " + port['state']['@reason'])
            print("     [+] TTL : " + port['state']['@reason_ttl'])
            print(colortext.ENDC)
        try:
            if port['state']['@state'] == 'open':
                services = ser_analysis(port['service'])
        except:
            pass

        return True
    except:
        returnerror()

filzrez = []
for r, d, f in os.walk(sys.argv[1]):
    for file in f:
        if '.xml' in file:
            fz = os.path.join(r, file)
            filzrez.append(fz)


for ff in filzrez:
    print('\n')
    print(colortext.OKYellow + "[*] Checking For " + ff + colortext.ENDC)
    ss = xml2json(ff)
    if ss:
        stat = getstatus(ss)
        if stat:
            status = stat['hosts'] + " Hosts Scanned " + stat['scanned'] + " Is Up"
            print(colortext.OKLight + "[*] Status : " + status + colortext.ENDC)
            if stat['hosts'] == '1':
                ports = getports(ss)
                if ports:
                    for port in ports:
                        portdata = port_analysis(port)
                else:
                    ww = port_analysis2(ss)
                    #no ports open
                print('\n')
            else:

                pass
    if searchsploirtcheck():
        print(colortext.OKYellow + "[*] Checking for Public Exploits " + colortext.ENDC)
        getexploits(ff)
    else:
        pass
