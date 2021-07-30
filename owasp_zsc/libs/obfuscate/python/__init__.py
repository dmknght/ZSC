"""
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp_zsc[at]googlegroups[dot]com ]
"""
import os
from owasp_zsc.new_cores import base_module


class Obfuscator(base_module.BaseModule):
    method = base_module.OptStringFromList("", "Obfuscate methods", [os.path.splitext(x)[0] for x in
                                                                     os.listdir(__path__[0]) if x.endswith(".py") and
                                                                     not x.startswith("__")])
    encode_times = base_module.OptInt(1, "Encode times")
