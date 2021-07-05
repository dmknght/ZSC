
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


def encode(data, times):
    # Imports that are needed to run our script
    requires_import = ["use MIME::Base64 qw(decode_base64);"]

    # We try to parse the code from script. We skip comments and split import to other code
    code_import, code_orig = "", ""
    for line in data.split("\n"):
        if line.startswith("use"):
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
    val_name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    var_str = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    var_data = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    func_name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
    func_argv = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))

    # Generate encoded payload
    eval_text = '$' + val_name
    encoded_payload = '$' + val_name + ' = "' + str(binascii.b2a_base64(code_orig.encode(
        'latin-1')).decode('latin-1').replace('\n', '')) + '";\n'

    f = code_import + f"\n{encoded_payload}\n\n"
    f += f"sub {func_name} " + "{\n"
    f += f"    {func_argv} = shift;"
    f += f"    {var_str} = decode_base64({func_argv});\n"
    f += f"    return {var_str};\n"
    f += "}\n"
    f += f"{var_data} = {eval_text};\n"
    f += f"eval {func_name}({var_data});\n"

    return f


def start(content, times):
    return str(encode(content, times))
