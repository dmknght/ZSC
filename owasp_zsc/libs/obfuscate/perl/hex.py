
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
    eval_text = ''
    n = 0
    m = 0
    for line in f:
        hex_arr.append(str((binascii.b2a_hex(str(line).encode('latin-1'))).decode('latin-1')))
    length = len(hex_arr)
    while length != 0:
        val_names.append(''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50)))
        length -= 1
    for hex_text in hex_arr:
        data += '$' + val_names[n] + ' = "' + str(hex_text) + '";\n'
        n += 1
    while m <= n - 1:
        eval_text += '$' + val_names[m] + '.'
        m += 1
    var_str = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    var_counter = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    var_data = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    func_name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    func_argv = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))

    f = f"{data}\n"
    f += f"sub {func_name} " + "{\n"
    f += f"    {func_argv} = shift;"
    f += f"    for({var_counter} = 0; {var_counter} < length {func_argv}; {var_counter} += 2) " + "{\n"
    f += f"        {var_str} .= chr(hex(substr({func_argv}, {var_counter}, 2)));\n"
    f += "    }\n"
    f += f"    return {var_str};\n"
    f += "}\n"
    f += f"{var_data} = {eval_text[:-1]};\n"
    f += f"eval {func_name}({var_data});\n"

    return f


def start(content, times):
    return str(str('=begin\n') + str(content.replace(
        '=begin', '#=begin').replace('=cut', '#=cut')) + str('\n=cut') + str(encode(content)) + str('\n'))
