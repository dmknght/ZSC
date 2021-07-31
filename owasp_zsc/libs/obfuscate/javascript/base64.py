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
        # base64_arr = ''
        val_name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        data = binascii.b2a_base64(data.encode('latin-1')).decode('latin-1').replace('\n', '')
        data = f"{val_name} = \" {data}\""
        var_b64 = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        var_str = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        var_data = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        func_name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        func_argv = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))

        data = f"{data}\n"
        data += f"function {func_name}({func_argv}) " + "{\n"
        data += f"    var {var_b64} = {func_argv}.toString();\n"
        data += f"    var {var_str} = window.atob({var_b64})\n"
        data += f"    return {var_str};\n" + "\n}\n"
        data += f"{var_data} = {val_name};\n"
        data += f"eval({func_name}({var_data}));\n"

        return data


    def start(self, content):
        return str(self.encode(content))
