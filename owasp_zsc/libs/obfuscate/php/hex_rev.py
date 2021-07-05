
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
	var_name = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
	rev_data = binascii.b2a_hex(f.encode('utf8')).decode('utf8')[::-1]
	data = var_name + ' = "' + rev_data + '";\n'

	var_str = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
	var_counter = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
	var_data = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
	func_name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
	func_argv = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
	f = f"{data}\n"
	f += f"function {func_name}({func_argv}) " + "{\n"
	f += f"	{var_str} = '';\n"
	f += f"	for({var_counter}=strlen({func_argv})-2;{var_counter}>=0;{var_counter}-=2)\n"
	f += f"	   {var_str} .= chr(hexdec(strrev(substr({func_argv},{var_counter},2))));\n"
	f += f"	return {var_str};\n"
	f += "}\n"
	f += f"{var_data} = {var_name};\n"
	f += f"eval({func_name}({var_data}));\n"
	f += "?>\n"

	return f


def start(content, times):
	if '<?' in content or '?>' in content or '<?php' in content:
		content = content.replace('<?php', '').replace('<?', '').replace('?>', '')
	return str(str('<?php \n/*\n') + str(content.replace('*/', '*_/')) + str('\n*/') + str(encode(content)) + str('\n'))
