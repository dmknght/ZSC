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
    time = base_module.OptInt(1, "How many self.time obfuscate runs")

    def encode(self, data):
        # Imports that are needed to run our script
        requires_import = ["import binascii", "import sys"]

        # We try to parse the code from script. We skip comments and split import to other code
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
        func_name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        func_argv = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        index_name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        tmp_name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))

        # Generate encoded payload
        encoded_payload = code_orig
        for i in range(0, self.times):
            encoded_payload = binascii.b2a_hex(encoded_payload.encode('utf8')).decode('utf8')
        final_encoded_payload = f"{var_name} = \"{str(encoded_payload)}\"\n"

        # Generate source code
        f = code_import + f"\n{final_encoded_payload}\n\n"
        f += f"def {func_name}({func_argv}):\n"
        f += "    if sys.version_info.major == 2:\n"
        f += f"        {tmp_name} = {func_argv}\n"
        f += f"        for {index_name} in xrange(0, {self.times}):\n"
        f += f"            {tmp_name} = str(binascii.a2b_hex({tmp_name}))\n"
        f += f"        return {tmp_name}\n"
        f += "    elif sys.version_info.major == 3:\n"
        f += f"        {tmp_name} = {func_argv}\n"
        f += f"        for {index_name} in range(0, {self.times}):\n"
        f += f"            {tmp_name} = str(binascii.a2b_hex({tmp_name}).decode('utf8'))\n"
        f += f"        return {tmp_name}\n"
        f += "    else:\n"
        f += "        sys.exit()\n"
        f += f"exec({func_name}({var_name}))\n"
        return f

    def start(self, content):
        return str(self.encode(content))

