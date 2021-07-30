"""
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp_zsc[at]googlegroups[dot]com ]
"""
from owasp_zsc.new_cores import color


def info(content):
    print(f"{color.color('yellow')} [+] {color.color('green')} {content} {color.color('reset')}")


def write(content):
    print(content)


def warn(content):
    print(f"{color.color('red')} [!] {color.color('yellow')} {content} {color.color('reset')}")


def error(content):
    print(f"{content}")
