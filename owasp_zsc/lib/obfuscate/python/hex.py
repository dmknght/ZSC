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
    hex_arr = []
    val_names = []
    data = ''
    eval_value = ''
    n = 0
    m = 0
    for line in f:
        hex_arr.append(binascii.b2a_hex(str(line).encode('utf8')).decode('utf8'))
    length = len(hex_arr)
    while length != 0:
        val_names.append(''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50)))
        length -= 1
    for hex_value in hex_arr:
        data += val_names[n] + ' = "' + str(hex_value) + '"\n'
        n += 1
    while m <= n - 1:
        eval_value += 'str(' + val_names[m] + ')+'
        m += 1
    # var_hex = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    var_data = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    func_name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    func_argv = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))

    f = "import binascii\n"
    f += "import sys\n"
    f += f"{data}\n"
    f += f"def {func_name}({func_argv}):\n"
    f += "  if sys.version_info.major == 2:\n"
    f += f"      return str(binascii.a2b_hex({func_argv}))\n"
    f += "  elif sys.version_info.major == 3:\n"
    f += f"      return str(binascii.a2b_hex({func_argv}).decode('utf8'))\n"
    f += "  else:\n"
    f += "      sys.exit('Your python version == not supported!')\n"
    f += f"{var_data} = {eval_value[:-1]}\n"
    f += f"exec({func_name}({var_data}))\n"
    return f


def start(content):
    return str(encode(content))
