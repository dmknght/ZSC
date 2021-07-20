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

    rev_data = binascii.b2a_hex(f.encode('utf8')).decode('utf8')[::-1]
    data = var_name + ' = "' + str(rev_data) + '"'

    var_data = random.choice(string.ascii_lowercase) + ''.join(
        random.choice(string.ascii_lowercase + string.ascii_uppercase)
        for i in range(50))
    func_name = ''.join(
        random.choice(string.ascii_lowercase + string.ascii_uppercase)
        for i in range(50))
    func_argv = random.choice(string.ascii_lowercase) + ''.join(
        random.choice(string.ascii_lowercase + string.ascii_uppercase)
        for i in range(50))
    var_str = random.choice(string.ascii_lowercase) + ''.join(
        random.choice(string.ascii_lowercase + string.ascii_uppercase)
        for i in range(50))

    f = f"{data}\n"
    f += f"def {func_name}({func_argv})\n"
    f += f"  {var_str} = Array({func_argv}.reverse).pack('H*')\n"
    f += f"  return {var_str}\n"
    f += "end\n"
    f += f"{var_data} = {var_name}\n"
    f += f"eval({func_name}({var_data}))\n"
    return f


def start(content, times=1):
    return str(encode(content))
