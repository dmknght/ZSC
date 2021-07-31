
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
        # Imports that are needed to run our script
        # We try to parse the code from script. We skip comments and split import to other code
        code_import, code_orig = "", ""
        for line in data.split("\n"):
            if line.startswith("use"):
                code_import += line + "\n"
            elif line.startswith("#"):
                pass
            else:
                code_orig += line + "\n"

        # Generate random strings
        var_name = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        var_str = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        var_data = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        var_ascii = '@' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        var_value = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        func_name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
        func_argv = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))

        # Generate encoded payload
        ascii_data = ''.join([str(ord(i))+'*' for i in code_orig])[:-1]
        encoded_payload = var_name + ' = "' + ascii_data + '";\n'

        f = code_import + f"\n{encoded_payload}\n\n"
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

    def start(self, content):
        return str(self.encode(content))
