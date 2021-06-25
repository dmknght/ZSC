
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


def encode(f):
	val_name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
	eval_text = '$' + val_name
	data = '$' + val_name + ' = "' + str(binascii.b2a_base64(f.encode(
		'latin-1')).decode('latin-1').replace('\n', '')) + '";\n'

	var_str = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
	var_data = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
	func_name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
	func_argv = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
	f = f"{data}\n"
	f += f"function {func_name}({func_argv}) " + "{\n"
	f += f"	{var_str} = base64_decode({func_argv});\n"
	f += f"	return {var_str};\n"
	f += "}\n"
	f += f"{var_data} = {eval_text};\n"
	f += f"eval({func_name}({var_data}));"
	f += "?>\n"

	return f


def start(content):
	if '<?' in content or '?>' in content or '<?php' in content:
		content = content.replace('<?php', '').replace('<?', '').replace('?>', '')
	return str(str('<?php \n/*\n') + str(content.replace('*/', '*_/')) + str(
		'\n*/') + str(encode(content)) + str('\n'))
