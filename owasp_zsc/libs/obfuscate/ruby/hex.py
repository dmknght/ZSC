
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
        hex_arr = []
        val_names = []
        data = ''
        eval_str = ''
        n = 0
        m = 0
        for line in data:
            hex_arr.append(str((binascii.b2a_hex(str(line).encode('latin-1'))
                                ).decode('latin-1')))
        length = len(hex_arr)
        while length != 0:
            val_names.append(random.choice(string.ascii_lowercase) + ''.join(
                random.choice(string.ascii_lowercase + string.ascii_uppercase)
                for i in range(50)))
            length -= 1
        for hex_str in hex_arr:
            data += val_names[n] + ' = "' + str(hex_str) + '"\n'
            n += 1
        while m <= n - 1:
            eval_str += val_names[m] + '.to_s + '
            m += 1
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

        data = f"{data}\n"
        data += f"def {func_name}({func_argv})\n"
        data += f"  {var_str} = Array({func_argv}).pack('H*')\n"
        data += f"  return {var_str}\n"
        data += "end\n"
        data += f"{var_data} = {eval_str[:-2]}\n"
        data += f"eval({func_name}({var_data}))\n"
        return data

    def start(self, content):
        return str(self.encode(content))
