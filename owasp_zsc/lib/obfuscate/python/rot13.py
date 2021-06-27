
"""
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp_zsc[at]googlegroups[dot]com ]
"""
import random
import string
import codecs


def encode(f):
    var_name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    rev_data = codecs.encode(f, "rot-13")
    data = var_name + ' = """' + str(rev_data) + '"""'

    func_name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    func_argv = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))

    f = "import binascii\n"
    f += "import sys\n"
    f += "import codecs\n"
    f += f"{data}\n"
    f += f"def {func_name}({func_argv}):\n"
    f += "    if sys.version_info.major == 2:\n"
    f += f"        return str({func_argv}.decode(\"rot13\"))\n"
    f += "    elif sys.version_info.major == 3:\n"
    f += f"        return str(codecs.decode({func_argv}, \"rot-13\"))\n"
    f += "    else:\n"
    f += "        sys.exit('Your python version == not supported!')\n"
    f += f"exec({func_name}({var_name}))\n"
    return f


def start(content, times):
    return str(encode(content))
