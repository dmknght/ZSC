
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
    var_name = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    ascii_data = ''.join([str(ord(i))+'*' for i in f])[:-1]
    data = var_name + ' = "' + ascii_data + '";\n'
    var_str = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    var_data = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    var_ascii = '@' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    var_value = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    func_name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    func_argv = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))

    f = f"{data}\n"
    f += f"sub {func_name} " + "{\n"
    f += f"    {func_argv} = shift;\n"
    f += f"    {var_str} = '';\n"
    f += f"    {var_ascii} = split /\\*/, {func_argv};\n"
    f += f"    foreach my {var_value} ({var_ascii}) " + "{\n"
    f += f"       {var_str} .= chr({var_value});\n"
    f += "    }\n"
    f += f"    return {var_str};\n"
    f += "}\n"
    f += f"{var_data} = {var_name};\n"
    f += f"eval {func_name}({var_data});\n"

    return f


def start(content):
    return str(str('=begin\n') + str(content.replace(
        '=begin', '#=begin').replace('=cut', '#=cut')) + str('\n=cut') + str(encode(content)) + str('\n'))
