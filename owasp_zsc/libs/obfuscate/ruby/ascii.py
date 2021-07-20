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
    var_name = ''.join(
        random.choice(string.ascii_lowercase + string.ascii_uppercase)
        for i in range(50))
    ascii_data = ''.join([str(ord(i)) + '*' for i in f])[:-1]
    data = var_name + ' = "' + ascii_data + '"'
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
    var_counter = random.choice(string.ascii_lowercase) + ''.join(
        random.choice(string.ascii_lowercase + string.ascii_uppercase)
        for i in range(50))
    var_ascii = random.choice(string.ascii_lowercase) + ''.join(
        random.choice(string.ascii_lowercase + string.ascii_uppercase)
        for i in range(50))

    f = f"{data}\n"
    f += f"def {func_name}({func_argv})\n"
    f += f"  {var_str} = ''\n"
    f += f"  {var_ascii} = {func_argv}.split('*')\n"
    f += f"  for {var_counter} in {var_ascii}\n"
    f += f"    {var_str} += {var_counter}.to_i.chr\n"
    f += "  end\n"
    f += f"  return {var_str}"
    f += "end\n"
    f += f"{var_data} = {var_name};\n"
    f += f"eval({func_name}({var_data}));\n"
    return f


def start(content, times=1):
    return str(encode(content))
