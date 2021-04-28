"""
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp-zsc[at]googlegroups[dot]com ]
"""
import sys
from cores import color


def info(content):
    sys.stdout.write(f"{color.color('yellow')} [+] {color.color('green')} {content} {color.color('reset')}\n")


def write(content):
    sys.stdout.write(content)


def warn(content):
    sys.stdout.write(f"{color.color('red')} [!] {color.color('yellow')} {content} {color.color('reset')}\n")


def error(content):
    sys.stdout.write(content)
