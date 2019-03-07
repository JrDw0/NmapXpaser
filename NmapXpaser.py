# !/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import os
import re

__author__ = 'JrD'
__time__ = '2019.03.07'

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET


def xmlparser(path=None):
    cwd = os.getcwd()
    absolute_path = os.path.join(cwd, path)
    if os.path.exists(absolute_path):
        filepath = (cwd+'/'+path.split('/')[-1].split('.')[0]+'.csv')
        if os.path.splitext(absolute_path)[-1].lower() == '.xml':
            with open('%s'%(filepath),'w') as write:
                try:
                    tree = ET.ElementTree(file=absolute_path)
                except ET.ParseError:
                    with open(absolute_path, 'a+') as file:
                        file.write('\n</nmaprun>')
                    tree = ET.ElementTree(file=absolute_path)
                root = tree.getroot()
                print('Nmap command: ' + root.attrib['args'])
                print('Start time: ' + root.attrib['startstr'])
                ADDR,PORT,STATE,SERVICE,PRODUCT,VERSION = 'ADDR','PORT','STATE','SERVICE','PRODUCT','VERSION'
                column_name = ('%-20s %-7s %-10s %-15s %-20s %-30s' %(ADDR,PORT,STATE,SERVICE,PRODUCT,VERSION))
                write.write('''%s,%s,%s,%s,%s,%s'''%(ADDR,PORT,STATE,SERVICE,PRODUCT,VERSION))
                print(column_name)
                for host in root.iter('host'):
                    addr = host[1].attrib['addr']
                    for ports in host[3][1:]:
                        port, state, service, product, version = '','','','',''
                        try:
                            port = ports.attrib['portid']
                            state = ports[0].attrib['state']
                            service = ports[1].attrib['name']
                            product = ports[1].attrib['product']
                            version = ports[1].attrib['version']
                        except KeyError:
                            pass
                        print('%-20s %-7s %-10s %-15s %-20s %-30s'% (addr,port,state,service,product,version))
                        write.write('''\n%s,%s,%s,%s,%s,%s''' % (addr,port,state,service,product,version))

            print('Finished: %s' % filepath)
        else:
            print('[ERROR] File is not XML: %s' % path)
    else:
        print('[ERROR] File not found: %s' % path)


if __name__ == '__main__':
    print('''                         
 | \ | |  _ __ ___     __ _   _ __   \ \/ /  _ __     __ _   ___    ___   _ __
 |  \| | | r'_ ` _ \   / _` | | '_ \  \  /  | r'_ \  / _` | / __|  / _ \ | '__|
 | |\  | | | | | | | | (_| | | |_) |  /  \  | |_) | | (_| | \__ \ |  __/ | |
 |_| \_| |_| |_| |_|  \__,_| | .__/  /_/\_\ | .__/   \__,_| |___/  \___| |_|
                             |_|            |_|                                ''')
    if len(sys.argv) == 2:
        xmlpath = sys.argv[1]
        xmlparser(path=xmlpath)
    else:
        print('''[usage]:python NmapXpaser.py xxxxxx.xml''')
        sys.exit()
