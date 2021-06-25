
"""
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp_zsc[at]googlegroups[dot]com ]
"""
import random
import string


def encode(f):
    var_name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    ascii_data = ''.join([str(ord(i))+'*' for i in f])[:-1]
    data = var_name + ' = "' + ascii_data + '"'
    var_counter = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    var_str = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    func_name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    func_argv = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))

    f = f"{data}\n"
    f += f"def {func_name}({func_argv}):\n"
    f += f"    {var_str} = ''\n"
    f += f"    for {var_counter} in {func_argv}.split('*'):\n"
    f += f"        {var_str} += chr(int({var_counter}))\n"
    f += f"    return {var_str}\n"
    f += f"exec({func_name}({var_name}))\n"
    return f


def start(content):
    return str(encode(content))
