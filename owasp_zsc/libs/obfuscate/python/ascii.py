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
    times = base_module.OptInt(1, "How many self.times obfuscate runs")

    def encode(self, data):
        # We try to parse the code from script. We skip comments and split import to other code
        requires_import = ["import sys"]

        code_import, code_orig = "", ""
        for line in data.split("\n"):
            if line.startswith("import"):
                code_import += line + "\n"
            elif line.startswith("#"):
                pass
            else:
                code_orig += line + "\n"

        # Check if import is in the script. We don't want duplicate lines
        for need_to_import in requires_import:
            if need_to_import not in code_import:
                code_import += need_to_import + "\n"

        # Generate random strings
        var_name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        var_counter = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        var_str = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        func_name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        func_argv = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        index_name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        tmp_name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))

        # Generate encoded payload
        encoded_payload = code_orig
        for i in range(0, self.times):
            encoded_payload = ''.join([str(ord(i))+'*' for i in encoded_payload])[:-1]
        final_encoded_payload = f"{var_name} = \"{str(encoded_payload)}\"\n"

        # Generate source code
        f = f"{code_import}\n{final_encoded_payload}\n"
        f += f"def {func_name}({func_argv}):\n"
        f += "    if sys.version_info.major == 2:\n"
        f += f"        {tmp_name} = {func_argv}\n"
        f += f"        for {index_name} in xrange(0, {self.times}):\n"
        f += f"            {var_str} = ''\n"
        f += f"            for {var_counter} in {tmp_name}.split('*'):\n"
        f += f"                if {var_counter}:\n"
        f += f"                    {var_str} += chr(int({var_counter}))\n"
        f += f"            {tmp_name} = {var_str}\n"
        f += f"        return {tmp_name}.replace('*', '')\n"
        f += "    elif sys.version_info.major == 3:\n"
        f += f"        {tmp_name} = {func_argv}\n"
        f += f"        for {index_name} in range(0, {self.times}):\n"
        f += f"            {var_str} = ''\n"
        f += f"            for {var_counter} in {tmp_name}.split('*'):\n"
        f += f"                if {var_counter}:\n"
        f += f"                    {var_str} += chr(int({var_counter}))\n"
        f += f"            {tmp_name} = {var_str}\n"
        f += f"        return {tmp_name}.replace('*', '')\n"
        f += "    else:\n"
        f += "        sys.exit()\n"
        f += f"exec({func_name}({var_name}))\n"
        return f

    def start(self, content):
        return str(self.encode(content))
