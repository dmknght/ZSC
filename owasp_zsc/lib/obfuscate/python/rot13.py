
"""
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp_zsc[at]googlegroups[dot]com ]
"""
import random
import string
import codecs


def encode(data):
    # Imports that are needed to run our script
    requires_import = ["import binascii", "import sys", "import codecs"]

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

    # Generate encoded payload
    encoded_payload = codecs.encode(code_orig, "rot-13")
    final_encoded_payload = var_name + ' = """' + str(encoded_payload) + '"""'

    f = code_import + f"\n{final_encoded_payload}\n\n"
    f += f"def {func_name}({func_argv}):\n"
    f += "    if sys.version_info.major == 2:\n"
    f += f"        return str({func_argv}.decode(\"rot13\"))\n"
    f += "    elif sys.version_info.major == 3:\n"
    f += f"        return str(codecs.decode({func_argv}, \"rot-13\"))\n"
    f += "    else:\n"
    f += "        sys.exit('Your python version == not supported!')\n"
    f += f"exec({func_name}({var_name}))\n"
    return f


def start(content, times):
    if times != 1:
        print("rot13 encoder only supports 1 time only")
    return str(encode(content))
