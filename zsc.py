"""
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp-zsc[at]googlegroups[dot]com ]
"""
import sys
import os
from cores.compatible import *
from cores.start import logo
from cores.controller import _interface


def main():
    """ Main Fucntion """
    logo()  # zsc logo
    _interface()


if __name__ == "__main__":
    main()  # execute main function
