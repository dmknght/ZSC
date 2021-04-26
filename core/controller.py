"""
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp-zsc[at]googlegroups[dot]com ]
"""
from core import run
from core.commands import commands_help
from core.cli import _cli_start
import sys


def _interface():
    if len(sys.argv) == 1:
        run.engine(commands_help)  # run engine with user friendly interface
    else:
        _cli_start(commands_help)  # run engine with basic interface
