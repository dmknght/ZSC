
"""
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp_zsc[at]googlegroups[dot]com ]
"""
import binascii
import random
import string


def encode(f):
    var_name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    rev_data = binascii.b2a_base64(f.encode('utf8')).decode('utf8')[-2::-1]
    data = var_name + ' = "' + str(rev_data) + '"'

    func_name = ''.join(
        random.choice(string.ascii_lowercase + string.ascii_uppercase)
        for i in range(50))
    func_argv = ''.join(
        random.choice(string.ascii_lowercase + string.ascii_uppercase)
        for i in range(50))
    f = "import binascii\n"
    f += "import sys\n"
    f += f"{data}\n"
    f += f"def {func_name}({func_argv}):\n"
    f += "    if sys.version_info.major == 2:\n"
    f += f"        return str(binascii.a2b_base64({func_argv}[::-1]))\n"
    f += "    elif sys.version_info.major == 3:\n"
    f += f"        return str(binascii.a2b_base64({func_argv}[::-1]).decode('utf8'))[::-1]\n"
    f += "    else:\n"
    f += "         sys.exit()\n"
    f += f"exec({func_name}({var_name}))\n"

    return f


def start(content):
    print("Obfuscated script for python3 is broken. Skipping")
    return None
    return str(encode(content))
