"""
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp_zsc[at]googlegroups[dot]com ]
"""
import sys
from owasp_zsc.cores.alert import write

__version__ = '2.0.0'
__key__ = 'ST'
__release_date__ = 'Jun 25, 2021'

from owasp_zsc.cores import color


def logo():
    print(" _______  _______  _______ ")
    print("/ ___   )(  ____ \\(  ____ \\   ---[ \033[93mShellcode/Obfuscate Code Generator\033[0m  ]---")
    print(f"\\/   )  || (    \\/| (    \\/"
          f"   ---[ Version: \033[97m{__version__}\033[0m Release \033[37m{__release_date__}\033[0m ]---")
    print("    /   )| (_____ | |         ---[ Maintainer: \033[95mNông Hoàng Tú\033[0m           ]---")
    print("   /   / (_____  )| |         ---[ Email: \033[96mdmknght@parrotsec.org\033[0m \033[0m       ]---")
    print("  /   /        ) || |         ---[ License: \033[94mGPL-3\033[0m                      ]---")
    print(" /   (_/\\/\\____) || (____/\\   ---[ A fork of OWASP-ZSC for Python 3    ]---")
    print("(_______/\\_______)(_______/\n")
    print("--[ Original source: \033[94mhttps://github.com/Ali-Razmjoo/OWASP-ZSC\033[0m ]--")
    print("--[ Original author: \033[95mAli Razmjoo\033[0m    <\033[96mali.razmjoo@owasp.org\033[0m>   ]--\n")


def sig():
    print('''%s
|----------------------------------------------------------------------------|
|%sVisit%s https://www.%sowasp%s.org/index.php/OWASP_ZSC_Tool_Project ---------------|
|----------------------------------------------------------------------------|%s'''
          % (color.color('blue'), color.color('red'), color.color('blue'),
             color.color('red'), color.color('blue'), color.color('reset')))


def input_check():
    print(color.color('yellow') + '''
[+] Wrong input, Check Help Menu ,Execute: zsc ''' + color.color('red') + '-h'
          + '\n' + color.color('reset'))
    sys.exit(sig())


def about():
    write('\n')
    info = [
        ['Code', 'https://github.com/Ali-Razmjoo/OWASP-ZSC'], [
            'Contributors',
            'https://github.com/Ali-Razmjoo/OWASP-ZSC/graphs/contributors'
        ], ['API', 'http://api.z3r0d4y.com/'],
        ['Home', 'http://zsc.z3r0d4y.com/'],
        ['Mailing List',
         'https://groups.google.com/d/forum/owasp-zsc'],
        ['Contact US Now', 'owasp_zsc[at]googlegroups[dot]com']
    ]
    for section in info:
        write('%s%s%s: %s%s%s\n' %
              (color.color('red'), section[0], color.color('reset'),
               color.color('yellow'), section[1], color.color('reset')))
    sig()


def _version():
    write('\n')
    write('%sOWASP ZSC Version: %s%s\n' %
          (color.color('cyan'), color.color('red'), __version__))
    write('%sKey: %s%s\n' % (color.color('cyan'), color.color('red'), __key__))
    write('%sRelease Date: %s%s\n' %
          (color.color('cyan'), color.color('red'), __release_date__))
    sig()
