"""
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp_zsc[at]googlegroups[dot]com ]
"""
import random
import string
from owasp_zsc.new_cores import base_module


class ObfuscateModule(base_module.BaseModule):
    def encode(self, data):
        var_name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        ascii_data = ''.join([str(ord(i)) + '*' for i in data])[:-1]
        data = var_name + ' = "' + ascii_data + '"'
        var_data = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        var_counter = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        var_str = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        var_ascii = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        func_name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        func_argv = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        data = f"{data}\n"
        data += f"function {func_name}({func_argv})" + " {\n"
        data += f"   var {var_str} = '';\n"
        data += f"   var {var_ascii} = {func_argv}.split(\"*\");"
        data += f"   for(var {var_counter} = 0; {var_counter} < {var_ascii}.length; {var_counter}++)" + "{\n"
        data += f"      {var_str} += String.fromCharCode({var_ascii}[{var_counter}]);\n"
        data += "   }\n"
        data += f"   return {var_str};\n"
        data += "}\n"
        data += f"{var_data} = {var_name}\n"
        data += f"eval({func_name}({var_data}))\n"

        return data

    def start(self, content):
        return str(self.encode(content))
