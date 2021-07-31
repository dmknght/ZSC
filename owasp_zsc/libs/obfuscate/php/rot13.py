
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
from owasp_zsc.new_cores import base_module


class ObfuscateModule(base_module.BaseModule):
	def encode(self, data):
		val_name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
		eval_str = '$' + val_name

		data = '$' + val_name + "=<<<'EOT'" + str(codecs.encode(data, "rot-13")) + '\nEOT;\n'
		var_str = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
		# var_data = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
		func_name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
		func_argv = '$' + ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(50))
		data = f"{data}\n"
		data += f"function {func_name}({func_argv}) " + "{\n"
		data += f"	{var_str} = str_rot13({func_argv});\n"
		data += f"	return {var_str};\n"
		data += "}\n"
		data += f"eval({func_name}({eval_str}));\n"
		data += "?>\n"

		return data

	def start(self, content):
		if '<?' in content or '?>' in content or '<?php' in content:
			content = content.replace('<?php', '').replace('<?', '').replace('?>', '')
		return str(str('<?php \n/*\n') + str(content.replace('*/', '*_/')) + str('\n*/') + str(self.encode(content)) + str('\n'))
