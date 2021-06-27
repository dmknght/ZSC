
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
    val_name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))

    eval_text = '$' + val_name

    data = '$' + val_name + ' = "' + str(binascii.b2a_base64(f.encode(
        'latin-1')).decode('latin-1').replace('\n', '')) + '";\n'

    var_str = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    var_data = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    func_name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    func_argv = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    f = "use MIME::Base64 qw(decode_base64);\n"
    f += f"{data}\n"
    f += f"sub {func_name} " + "{\n"
    f += f"    {func_argv} = shift;"
    f += f"    {var_str} = decode_base64({func_argv});\n"
    f += f"    return {var_str};\n"
    f += "}\n"
    f += f"{var_data} = {eval_text};\n"
    f += f"eval {func_name}({var_data});\n"

    return f


def start(content, times):
    return str(str('=begin\n') + str(content.replace(
        '=begin', '#=begin').replace('=cut', '#=cut')) + str('\n=cut') + str(encode(content)) + str('\n'))
