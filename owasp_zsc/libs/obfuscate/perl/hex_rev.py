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
from owasp_zsc.new_cores import base_module


class ObfuscateModule(base_module.BaseModule):
    def encode(self, data):
        var_name = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        rev_data = binascii.b2a_hex(data.encode('utf8')).decode('utf8')[::-1]
        data = var_name + ' = "' + rev_data + '";\n'

        var_str = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        var_counter = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        var_data = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        var_rev = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        func_name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        func_argv = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        data = f"{data}\n"
        data += f"sub {func_name} " + "{\n"
        data += f"    {func_argv} = shift;\n"
        data += f"    {var_rev} = reverse {func_argv};\n"
        data += f"    for({var_counter} = 0; {var_counter} < length {var_rev}; {var_counter} += 2) " + "{\n"
        data += f"        {var_str} .= chr(hex(substr({var_rev}, {var_counter}, 2)));\n"
        data += "    }\n"
        data += f"    return {var_str};\n"
        data += "}\n"
        data += f"{var_data} = {var_name};\n"
        data += f"eval {func_name}({var_data});\n"

        return data


    def start(self, content):
        return str(self.encode(content))
