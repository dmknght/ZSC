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
    # base64_arr = ''
    val_name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    # data = ''

    data = val_name + '= `' + str(codecs.encode(f, "rot-13")) + '`;'
    # var_b64 = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    # var_str = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    # var_data = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    func_name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    func_argv = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))

    f = f"{data}\n"
    f += "function rot(s) {\n"
    f += "    return s.replace(/[a-zA-Z]/g, function (c) {\n"
    f += "        return String.fromCharCode((c <= \"Z\" ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26);\n"
    f += "    });\n}\n"
    f += f"function {func_name}({func_argv})" + " {\n"
    f += f"    return rot({func_argv});\n" + "}\n"
    f += f"eval({func_name}({val_name}));\n"

    return f


def start(content):
    return str(str('/*\n') + str(content.replace('*/', '*_/')) + str('\n*/') +
               str(encode(content)) + str('\n'))
